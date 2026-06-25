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


function analyseURL(url) {
    let score = 0;
    const flags = []

    let parsed;
    try {
       parsed = new URL(url)
    } catch {
        return { score: 0, flags: [], verdict: 'safe' };
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
chrome.tabs.onUpdated.addListener(
    (tabId, changeInfo, tab) => {

        //page must complete loading and tab must have valid url
        if (changeInfo.status != 'complete' || !tab.url) return;

        const result = analyseURL(tab.url);
        console.log(result);

        chrome.storage.local.set({ [tabId]: result });
    }
)