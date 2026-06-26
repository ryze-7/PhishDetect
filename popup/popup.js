document.addEventListener('DOMContentLoaded', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tabId = tabs[0].id.toString();

        function displayResult(result) {
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
        }

        // Read immediately
        chrome.storage.local.get(tabId, (data) => {
            displayResult(data[tabId]);
        });

        // Update if storage changes while popup is open
        chrome.storage.onChanged.addListener((changes) => {
            if (changes[tabId]) {
                displayResult(changes[tabId].newValue);
            }
        });

        
    });
});