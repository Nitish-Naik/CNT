chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'search') {
        chrome.tabs.create({ url: 'https://www.bing.com/' }, (tab) => {
            chrome.tabs.onUpdated.addListener(function checkTabUpdate(updatedTabId, changeInfo) {
                if (updatedTabId === tab.id && changeInfo.status === 'complete') {
                    chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        function: performSearch
                    });
                    chrome.tabs.onUpdated.removeListener(checkTabUpdate);
                }
            });
        });
    }
});

function performSearch() {
    const query = 'Microsoft Rewards'; // Customize your query here
    const searchInput = document.querySelector('input[name="q"]');
    if (searchInput) {
        searchInput.value = query;
        searchInput.form.submit();
    }
}
