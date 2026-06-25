document.addEventListener('DOMContentLoaded', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tabId = tabs[0].id;
        chrome.storage.local.get(tabId.toString(), (data) => {
            const result = data[tabId.toString()];

            const verdictEl = document.getElementById('verdict');
            const scoreEl = document.getElementById('score');
            const flagsEl = document.getElementById('flags');

            if (!result) {
                verdictEl.textContent = 'NOT ANALYSED';
                scoreEl.textContent = 'Reload the page to scan';
                verdictEl.style.color = 'gray';
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
        });
    });
});