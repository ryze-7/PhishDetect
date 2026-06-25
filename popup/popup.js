document.addEventListener('DOMContentLoaded', () => {
    let currentTabId = null;

    function render(result) {
        const verdictEl = document.getElementById('verdict');
        const scoreEl = document.getElementById('score');
        const flagsEl = document.getElementById('flags');

        if (!result) {
            verdictEl.textContent = 'SCANNING...';
            scoreEl.textContent = 'Analysing page content';
            verdictEl.style.color = 'gray';
            flagsEl.textContent = '';
            return;
        }

        verdictEl.textContent = result.verdict.toUpperCase();
        scoreEl.textContent = `Score: ${result.score}`;
        flagsEl.textContent = result.flags.length
            ? result.flags.join('\n')
            : 'No flags detected';

        if (result.verdict === 'block') verdictEl.style.color = 'red';
        else if (result.verdict === 'warn') verdictEl.style.color = 'orange';
        else verdictEl.style.color = 'green';
    }

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        currentTabId = tabs[0].id;
        const key = currentTabId.toString();

        chrome.storage.local.get(key, (data) => render(data[key]));

        // Force a fresh scan right now in case the popup was opened
        // before the debounced MutationObserver scan completed.
        chrome.tabs.sendMessage(currentTabId, { type: 'REQUEST_RESCAN' }, () => {
            // swallow "no receiving end" errors on pages where content.js
            // didn't inject (chrome:// pages, the Web Store, etc.)
            if (chrome.runtime.lastError) { /* no-op */ }
        });
    });

    // Live update: re-render if background.js writes a new result for
    // this tab while the popup is already open.
    chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName !== 'local' || currentTabId === null) return;
        const key = currentTabId.toString();
        if (changes[key]) {
            render(changes[key].newValue);
        }
    });
});