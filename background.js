// Suspicious TLDs commonly abused in phishing
const SUSPICIOUS_TLDS = ['.top', '.xyz', '.cc', '.click', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov'];

// Target brands & Brand safe domains
const TARGET_BRANDS = ['paypal', 'netflix', 'google', 'microsoft', 'amazon', 'apple', 'facebook', 'instagram', 'discord', 'steam'];

//currently limited to top 10 Brands, later is just data entry part
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
    steam: ['steampowered.com', 'steamcommunity.com']
};

let ALLOWLIST = [];

fetch(chrome.runtime.getURL('data/allowlist.json'))
    .then(res => res.json())
    .then(data => { ALLOWLIST = data; })
    .catch(err => console.error('Failed to load allowlist:', err));


let BLOCKLIST = [];

fetch(chrome.runtime.getURL('data/blocklist.json'))
    .then(res => res.json())
    .then(data => { BLOCKLIST = data; })
    .catch(err => console.error('Failed to load blocklist:', err));

function analyseURL(url) {
    let score = 0;
    const flags = []

    let parsed;
    try {
       parsed = new URL(url)
    } catch {
        return { score: 0, flags: [], verdict: 'safe' };
    }

    const isAllowlisted = ALLOWLIST.some(domain => 
        parsed.hostname === domain || parsed.hostname.endsWith('.' + domain)
    );

    if (isAllowlisted) {
        return { score: 0, flags: ['Allowlisted domain'], verdict: 'safe' };
    }

    const isBlocklisted = BLOCKLIST.some(domain =>
        parsed.hostname === domain || parsed.hostname.endsWith('.' + domain)
    );

    if (isBlocklisted) {
        return { score: 10, flags: ['Blocklisted domain'], verdict: 'block' };
    }
    
    //Checking subdomain depth
    const parts = parsed.hostname.split('.');

    //more then 4 is likely more suspicious then more than 3
    if (parts.length > 4) {
        score+=4;
        flags.push(`Deep subdomain: ${parts.length} parts`);
    }
    else if (parts.length > 3) {
        score+=2;
        flags.push('Elevated subdomain depth');
    }

    //brand spoofing
    for (const brand of TARGET_BRANDS) {
        if (parsed.hostname.includes(brand)) {
            const safeDomain = BRAND_SAFE_DOMAINS[brand];

            // parsed.hostname === d -> Gives exact match
            // parsed.hostname.endsWith('.' + d) checks for mail.google.com, prevents bad domains like evilgoogle.com with '.'

            const isSafe = safeDomain.some(d => parsed.hostname === d || parsed.hostname.endsWith('.' + d));
            if (!isSafe) {
                score += 6;
                flags.push(`Brand spoof: "${brand}" in URL but not on official domain`)
            }
        }
    }

    //httpS(ecure) check
    if (parsed.protocol === 'http:') {
        score += 2;
        flags.push('Non-secure connection (HTTP)');
    }

    //Checking if hostname is an IP Address
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(parsed.hostname)) {
        score += 5;
        flags.push('IP address used as hostname');
    }

    //Verdict Threshold
    let verdict;
    if (score >= 8) verdict = 'block';
    else if (score >=4) verdict = 'warn';
    else verdict = 'safe';

    //currently hardcoded console values for url
    return { score, flags, verdict };
}


//listening events generated after visiting a tab 
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== 'complete' || !tab.url) return;
    if (!tab.url.startsWith('http')) return;

    // Clear previous result for this tab first
    chrome.storage.local.remove(tabId.toString());

    const result = analyseURL(tab.url);
    chrome.storage.local.set({ [tabId]: result });
    console.log(`[PhishDetect] ${tab.url}`);
    console.log(`Score: ${result.score} | Verdict: ${result.verdict}`);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type !== 'DOM_FLAGS') return;
    if (!message.flags.length) return;

    const tabId = sender.tab.id;

    chrome.storage.local.get(tabId.toString(), (data) => {
        const existing = data[tabId.toString()];
        if (!existing) return;

        existing.flags.push(...message.flags);
        existing.score += message.flags.length * 3;

        if (existing.score >= 8) existing.verdict = 'block';
        else if (existing.score >= 4) existing.verdict = 'warn';

        chrome.storage.local.set({ [tabId]: existing });
    });
});