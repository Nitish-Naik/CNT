let intervalId;
let searchCount = 0;

document.getElementById('startBtn').addEventListener('click', () => {
    const numSearches = parseInt(document.getElementById('numSearches').value);
    if (isNaN(numSearches) || numSearches <= 0) {
        alert('Please enter a valid number of searches.');
        return;
    }

    document.getElementById('startBtn').disabled = true;
    document.getElementById('stopBtn').disabled = false;

    searchCount = numSearches;

    // Start searching
    performSearches();
});

document.getElementById('stopBtn').addEventListener('click', () => {
    clearInterval(intervalId);
    document.getElementById('startBtn').disabled = false;
    document.getElementById('stopBtn').disabled = true;
});

function performSearches() {
    if (searchCount > 0) {
        chrome.runtime.sendMessage({ action: 'search' });
        searchCount--;

        // Schedule the next search after 60 seconds (adjust as needed)
        intervalId = setTimeout(performSearches, 60000);
    } else {
        clearInterval(intervalId);
        document.getElementById('startBtn').disabled = false;
        document.getElementById('stopBtn').disabled = true;
    }
}
