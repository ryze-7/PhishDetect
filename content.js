// ===== Shared scoring logic =====
const SUSPICIOUS_TLDS = ['.top', '.xyz', '.cc', '.click', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov'];

const TARGET_BRANDS = ['paypal', 'netflix', 'google', 'microsoft', 'amazon', 'apple', 'facebook', 'instagram', 'discord', 'steam','wikipedia'];

const BRAND_SAFE_DOMAINS = {
    paypal: ['paypal.com', 'paypal.co.uk'],
    netflix: ['netflix.com'],
    google: ['google.com', 'google.co.in', 'google.co.uk', 'googleapis.com', 'youtube.com'],
    microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
    amazon: ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazonaws.com'],
    apple: ['apple.com', 'icloud.com'],
    facebook: ['facebook.com', 'meta.com'],
    instagram: ['instagram.com'],
    discord: ['discord.com', 'discord.gg'],
    steam: ['steampowered.com', 'steamcommunity.com'],
    wikipedia: ['wikipedia.org', 'en.wikipedia.org']
};

function normalizeForBrandMatch(hostname) {
    return hostname
        .replace(/0/g, 'o')
        .replace(/1/g, 'i')
        .replace(/3/g, 'e')
        .replace(/5/g, 's')
        .replace(/4/g, 'a')
        .replace(/-/g, '');
}

function analyseURL(url) {
    let score = 0;
    const flags = [];

    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        return { score: 0, flags: [], verdict: 'safe', url };
    }

    const hostname = parsed.hostname;
    const normalizedHost = normalizeForBrandMatch(hostname);
    const parts = hostname.split('.');

    if (parts.length > 4) {
        score += 4;
        flags.push(`Deep subdomain: ${parts.length} parts`);
    } else if (parts.length > 3) {
        score += 2;
        flags.push('Elevated subdomain depth');
    }

    for (const brand of TARGET_BRANDS) {
        if (normalizedHost.includes(brand)) {
            const safeDomains = BRAND_SAFE_DOMAINS[brand];
            const isSafe = safeDomains.some(d => hostname === d || hostname.endsWith('.' + d));
            if (!isSafe) {
                score += 6;
                flags.push(`Brand spoof: "${brand}" in URL but not on official domain`);
            }
        }
    }

    if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
        score += 3;
        flags.push('Suspicious TLD');
    }

    if (parsed.protocol === 'http:') {
        score += 2;
        flags.push('Non-secure connection (HTTP)');
    }

    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
        score += 5;
        flags.push('IP address used as hostname');
    }

    let verdict;
    if (score >= 8) verdict = 'block';
    else if (score >= 4) verdict = 'warn';
    else verdict = 'safe';

    return { score, flags, verdict, url };
}

// ===== Form scanning =====
function scanForms() {
    const currentDomain = window.location.hostname;
    const forms = document.querySelectorAll('form');
    const domFlags = [];

    forms.forEach(form => {
        const hasPasswordField = form.querySelector('input[type="password"]');
        if (!hasPasswordField) return;

        const action = form.getAttribute('action');
        if (!action) return;

        try {
            const actionDomain = new URL(action, window.location.href).hostname;
            if (actionDomain && actionDomain !== currentDomain) {
                domFlags.push(`Form submits to different domain: ${actionDomain}`);
            }
        } catch {
            // invalid action URL, skip
        }
    });

    return domFlags;
}

// ===== Anchor link scanning =====
function scanLinks() {
    const anchors = document.querySelectorAll('a[href]');
    const results = [];

    anchors.forEach(a => {
        let href;
        try {
            href = a.href;
        } catch {
            return;
        }

        const result = analyseURL(href);
        if (result.verdict !== 'safe') {
            results.push({
                href: result.url,
                text: a.textContent.trim().slice(0, 100),
                score: result.score,
                flags: result.flags,
                verdict: result.verdict
            });
        }
    });

    return results;
}

// ===== Run scan and report to background =====
function runScan() {
    const suspiciousLinks = scanLinks();
    const formFlags = scanForms();

    // Score the page we're currently standing on (its own URL/protocol),
    // separate from links/forms found within it. This is what catches
    // plain http:// sites, IP-hosted pages, or a spoofed domain itself.
    const currentPageResult = analyseURL(window.location.href);

    chrome.runtime.sendMessage({
        type: 'PAGE_SCAN_RESULT',
        suspiciousLinks,
        formFlags,
        currentPageResult
    });
}

runScan();

let debounceTimer = null;
const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(runScan, 500);
});
observer.observe(document.documentElement, { childList: true, subtree: true });

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'REQUEST_RESCAN') {
        runScan();
        sendResponse({ ok: true });
    }
});