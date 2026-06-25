// background.js
// Scores are now driven entirely by content.js's scan of actual page
// content (links, forms) — not by tab.url, which only reflects the
// address bar and is meaningless for something like Gmail.

chrome.runtime.onMessage.addListener((msg, sender) => {
    if (msg.type !== 'PAGE_SCAN_RESULT' || !sender.tab) return;

    const tabId = sender.tab.id;
    const { suspiciousLinks, formFlags, currentPageResult } = msg;

    const linkScore = suspiciousLinks.reduce((max, l) => Math.max(max, l.score), 0);
    const formPenalty = formFlags.length > 0 ? 6 : 0;
    const pageScore = currentPageResult ? currentPageResult.score : 0;

    const totalScore = Math.max(linkScore, formPenalty, pageScore);

    let verdict;
    if (totalScore >= 8) verdict = 'block';
    else if (totalScore >= 4) verdict = 'warn';
    else verdict = 'safe';

    const allFlags = [
        ...(currentPageResult ? currentPageResult.flags : []),
        ...formFlags,
        ...suspiciousLinks.flatMap(l => l.flags)
    ];

    chrome.storage.local.set({
        [tabId.toString()]: {
            score: totalScore,
            flags: allFlags,
            verdict,
            suspiciousLinks
        }
    });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
        chrome.storage.local.remove(tabId.toString());
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    chrome.storage.local.remove(tabId.toString());
});