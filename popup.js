/* global browser */
/**
 * Popup script for quick queue access
 */

// DOM elements
const totalCount = document.getElementById('totalCount');
const pendingCount = document.getElementById('pendingCount');
const completedCount = document.getElementById('completedCount');
const processQueueBtn = document.getElementById('processQueue');
const viewQueueBtn = document.getElementById('viewQueue');
const clearQueueBtn = document.getElementById('clearQueue');
const openSettingsBtn = document.getElementById('openSettings');
const emptyState = document.getElementById('emptyState');
const queueActions = document.getElementById('queueActions');
const processingIndicator = document.getElementById('processingIndicator');

/**
 * Load and display queue stats
 */
async function loadQueueStats() {
    try {
        const response = await browser.runtime.sendMessage({ action: 'getUrlScanQueue' });
        
        if (response.success) {
            const queue = response.queue;
            const pending = queue.filter(item => item.status === 'pending').length;
            const completed = queue.filter(item => item.status === 'completed').length;
            const scanning = queue.filter(item => item.status === 'scanning').length;
            
            totalCount.textContent = queue.length;
            pendingCount.textContent = pending;
            completedCount.textContent = completed;
            
            // Show/hide elements based on queue state
            if (queue.length === 0) {
                emptyState.style.display = 'block';
                queueActions.style.display = 'none';
            } else {
                emptyState.style.display = 'none';
                queueActions.style.display = 'block';
                
                // Enable/disable buttons
                processQueueBtn.disabled = pending === 0;
                clearQueueBtn.disabled = false;
            }
            
            // Show processing indicator
            if (scanning > 0) {
                processingIndicator.style.display = 'block';
            } else {
                processingIndicator.style.display = 'none';
            }
        }
    } catch (error) {
        console.error('Failed to load queue stats:', error);
    }
}

/**
 * Process queue
 */
processQueueBtn.addEventListener('click', async () => {
    processQueueBtn.disabled = true;
    processQueueBtn.innerHTML = '<span style="animation: spin 1s linear infinite; display: inline-block;">⚙️</span> Processing...';
    
    await browser.runtime.sendMessage({ action: 'processQueue' });
    
    // Refresh stats periodically
    const refreshInterval = setInterval(() => {
        loadQueueStats();
    }, 2000);
    
    // Stop refreshing after 2 minutes
    setTimeout(() => {
        clearInterval(refreshInterval);
        processQueueBtn.disabled = false;
        processQueueBtn.innerHTML = '🚀 Process Queue';
        loadQueueStats();
    }, 120000);
});

/**
 * View queue (open settings)
 */
viewQueueBtn.addEventListener('click', () => {
    browser.runtime.openOptionsPage();
    window.close();
});

/**
 * Clear queue
 */
clearQueueBtn.addEventListener('click', async () => {
    if (confirm('Clear entire scan queue?')) {
        await browser.runtime.sendMessage({ action: 'clearQueue' });
        loadQueueStats();
    }
});

/**
 * Open settings
 */
openSettingsBtn.addEventListener('click', () => {
    browser.runtime.openOptionsPage();
    window.close();
});

// Load stats on popup open
loadQueueStats();

// Refresh every 3 seconds while popup is open
setInterval(loadQueueStats, 3000);

console.log('Popup initialized');
