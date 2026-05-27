/* global browser */
/**
 * URLScan.io & NextDNS Firefox Extension - Background Service Worker
 * Handles security tool integrations and context menu management
 */

// Store profiles for menu creation
let nextDnsProfiles = [];

// URLScan queue processing state
let isProcessingQueue = false;
let queueProcessCancelled = false;

/**
 * Submit a URL to urlscan.io for scanning
 * @param {string} url - The URL to scan
 * @param {boolean} fromQueue - Whether this scan is from queue processing
 */
async function sendToUrlscan(url, fromQueue = false) {
    const API_ENDPOINT = 'https://urlscan.io/api/v1/scan/';
    
    try {
        // Load settings from storage
        const { urlscanApiKey: apiKey, urlscanVisibility: visibility, urlscanTags: tags } = 
            await browser.storage.sync.get(['urlscanApiKey', 'urlscanVisibility', 'urlscanTags']);

        // Validate configuration
        if (!apiKey || !visibility) {
            notifyError('URLScan Configuration Missing', 'Please set your API key and visibility in the extension options.');
            return;
        }

        // Validate API key format (basic check)
        if (apiKey.length < 20) {
            notifyError('Invalid URLScan API Key', 'The API key appears to be invalid. Please check your settings.');
            return;
        }

        // Parse tags (default to firefox and extension if not set)
        let tagArray = ['firefox', 'extension'];
        if (tags && tags.trim()) {
            tagArray = tags.split(',').map(tag => tag.trim()).filter(tag => tag.length > 0);
            if (tagArray.length === 0) {
                tagArray = ['firefox', 'extension'];
            }
        }

        const payload = {
            url,
            visibility,
            tags: tagArray
        };

        // Submit scan request
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'API-Key': apiKey
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            const errorMessage = errorData.message || errorData.description || 'Unknown error from urlscan.io';
            notifyError(
                `URLScan API Error (${response.status})`,
                errorMessage
            );
            console.error('URLScan API Error:', errorData);
            return;
        }

        const data = await response.json();
        notifySuccess('URLScan submitted successfully! Opening results soon...');
        
        // Start polling for results
        if (data.uuid) {
            pollForScanResult(data.uuid, apiKey);
        } else {
            notifyError('Invalid Response', 'Did not receive a scan UUID from urlscan.io');
        }

    } catch (error) {
        console.error('URLScan unexpected error:', error);
        notifyError('URLScan Error', error.message || 'An unexpected error occurred. Please try again.');
    }
}

/**
 * Poll the urlscan.io API for scan results
 * @param {string} uuid - The scan UUID
 * @param {string} apiKey - The API key for authentication
 */
function pollForScanResult(uuid, apiKey) {
    const RESULT_ENDPOINT = `https://urlscan.io/api/v1/result/${uuid}/`;
    const POLL_INTERVAL = 2000; // 2 seconds
    const INITIAL_DELAY = 10000; // 10 seconds initial delay
    const MAX_ATTEMPTS = 20; // Stop after 40 seconds of polling

    let attempts = 0;
    let intervalId = null;

    /**
     * Check if scan results are ready
     */
    const checkResults = async () => {
        attempts++;
        
        try {
            const response = await fetch(RESULT_ENDPOINT, {
                headers: { 'API-Key': apiKey }
            });

            if (response.ok) {
                // Results are ready!
                clearInterval(intervalId);
                await browser.tabs.create({ 
                    url: `https://urlscan.io/result/${uuid}/`,
                    active: true
                });
                console.log(`URLScan completed successfully: ${uuid}`);
            } else if (response.status === 404) {
                // Scan not ready yet
                console.log(`URLScan not ready yet (attempt ${attempts}/${MAX_ATTEMPTS})...`);
                
                if (attempts >= MAX_ATTEMPTS) {
                    clearInterval(intervalId);
                    notifyError(
                        'URLScan Timeout', 
                        'The scan is taking longer than expected. You can check results manually at urlscan.io.'
                    );
                }
            } else {
                // Other error
                clearInterval(intervalId);
                const errorText = await response.text().catch(() => 'Unknown error');
                notifyError(
                    `URLScan Polling Error (${response.status})`, 
                    errorText
                );
                console.error('URLScan polling error:', response.status, errorText);
            }
        } catch (error) {
            clearInterval(intervalId);
            console.error('URLScan polling exception:', error);
            notifyError('Network Error', 'Failed to check URLScan results. Please check your connection.');
        }
    };

    // Start polling after initial delay
    setTimeout(() => {
        intervalId = setInterval(checkResults, POLL_INTERVAL);
    }, INITIAL_DELAY);
}

/**
 * Extract domain from URL or text
 * Handles special cases like URLScan.io result pages and Outlook Safe Links
 * @param {string} url - Full URL or text
 * @returns {string} Domain only
 */
function extractDomain(url) {
    try {
        // Check if this is an Outlook Safe Links URL
        // Format: https://*/safelinks.protection.outlook.com/?url=<encoded_url>&...
        if (url.includes('safelinks.protection.outlook.com') || 
            url.includes('nam.safelinks.protection.outlook.com') ||
            url.includes('emea.safelinks.protection.outlook.com') ||
            url.includes('apac.safelinks.protection.outlook.com') ||
            url.match(/[a-z]{2,4}\d{2}\.safelinks\.protection\.outlook\.com/)) {
            
            try {
                const urlObj = new URL(url);
                const actualUrl = urlObj.searchParams.get('url');
                if (actualUrl) {
                    const decodedUrl = decodeURIComponent(actualUrl);
                    console.log(`Outlook Safe Link detected. Original: ${url.substring(0, 80)}...`);
                    console.log(`Extracted actual URL: ${decodedUrl}`);
                    // Recursively extract domain from the actual URL
                    return extractDomain(decodedUrl);
                }
            } catch (error) {
                console.error('Failed to extract from Outlook Safe Link:', error);
            }
        }
        
        // Check if this is a URLScan.io result page
        // Format: urlscan.io/domain/example.com or urlscan.io/result/UUID
        if (url.includes('urlscan.io/domain/')) {
            const match = url.match(/urlscan\.io\/domain\/([^\/\?#]+)/);
            if (match && match[1]) {
                console.log(`URLScan.io domain page detected. Extracted: ${match[1]}`);
                return match[1];
            }
        }
        
        // If it's just a domain without protocol, return as-is
        if (!url.includes('://') && !url.includes('/')) {
            return url;
        }
        
        // Try to parse as URL
        const urlObj = new URL(url.includes('://') ? url : `https://${url}`);
        return urlObj.hostname;
    } catch (error) {
        // If URL parsing fails, try to extract domain-like pattern
        const domainMatch = url.match(/([a-z0-9-]+\.)+[a-z]{2,}/i);
        if (domainMatch) {
            console.log(`Extracted domain via regex: ${domainMatch[0]}`);
            return domainMatch[0];
        }
        console.error('Failed to extract domain:', error);
        return url;
    }
}

/**
 * Add domain to NextDNS list (blocklist or allowlist)
 * @param {string} profileId - NextDNS profile ID
 * @param {string} profileName - Profile name for display
 * @param {string} domain - Domain to add
 * @param {string} listType - 'denylist' or 'allowlist'
 * @param {boolean} silent - If true, don't show notifications (for bulk operations)
 */
async function addToNextDnsList(profileId, profileName, domain, listType, silent = false) {
    try {
        const { nextdnsApiKey: apiKey } = await browser.storage.sync.get(['nextdnsApiKey']);

        if (!apiKey) {
            if (!silent) {
                notifyError('NextDNS Configuration Missing', 'Please set your NextDNS API key in the extension options.');
            }
            return;
        }

        // NextDNS API endpoint - POST to add domain to list
        const endpoint = `https://api.nextdns.io/profiles/${profileId}/${listType}`;
        
        console.log(`Calling NextDNS API: POST ${endpoint} with domain: ${domain}`);
        
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'X-Api-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                id: domain,
                active: true
            })
        });

        console.log(`NextDNS API response: ${response.status}`);

        if (response.ok || response.status === 201 || response.status === 204) {
            const listName = listType === 'denylist' ? 'blocklist' : 'allowlist';
            if (!silent) {
                notifySuccess(`NextDNS: Added "${domain}" to ${listName} in profile "${profileName}"`);
            }
            console.log(`NextDNS: Successfully added ${domain} to ${listType} in profile ${profileId}`);
        } else {
            const errorText = await response.text().catch(() => 'Unknown error');
            if (!silent) {
                notifyError(
                    `NextDNS API Error: ${response.status}`,
                    errorText || 'Failed to add domain to list'
                );
            }
            console.error('NextDNS API Error:', response.status, errorText);
            throw new Error(`API Error ${response.status}`);
        }

    } catch (error) {
        console.error('NextDNS unexpected error:', error);
        if (!silent) {
            notifyError('NextDNS Error', error.message || 'An unexpected error occurred.');
        }
        throw error;
    }
}

/**
 * Fetch NextDNS profiles for the user
 * @returns {Array} Array of profile objects
 */
async function fetchNextDnsProfiles() {
    try {
        const { nextdnsApiKey: apiKey } = await browser.storage.sync.get(['nextdnsApiKey']);

        if (!apiKey) {
            console.log('NextDNS API key not configured in storage');
            return [];
        }

        console.log('Fetching NextDNS profiles with API key length:', apiKey.length);
        
        const response = await fetch('https://api.nextdns.io/profiles', {
            headers: {
                'X-Api-Key': apiKey
            }
        });

        console.log('NextDNS API response status:', response.status);

        if (response.ok) {
            const data = await response.json();
            const profiles = data.data || [];
            console.log('NextDNS profiles fetched successfully:', profiles.length, 'profiles');
            if (profiles.length > 0) {
                console.log('Profile names:', profiles.map(p => p.name || p.id).join(', '));
            }
            return profiles;
        } else {
            const errorText = await response.text().catch(() => 'No error text');
            console.error('Failed to fetch NextDNS profiles. Status:', response.status, 'Error:', errorText);
            return [];
        }

    } catch (error) {
        console.error('Exception while fetching NextDNS profiles:', error.message, error);
        return [];
    }
}

/**
 * Get URLScan queue from storage
 * @returns {Array} Queue items
 */
async function getUrlScanQueue() {
    try {
        const { urlscanQueue = [] } = await browser.storage.local.get(['urlscanQueue']);
        return urlscanQueue;
    } catch (error) {
        console.error('Failed to get URLScan queue:', error);
        return [];
    }
}

/**
 * Save URLScan queue to storage
 * @param {Array} queue - Queue items
 */
async function saveUrlScanQueue(queue) {
    try {
        await browser.storage.local.set({ urlscanQueue: queue });
    } catch (error) {
        console.error('Failed to save URLScan queue:', error);
    }
}

/**
 * Add URL to URLScan queue
 * @param {string} url - URL to add
 */
async function addToUrlScanQueue(url) {
    try {
        const queue = await getUrlScanQueue();
        
        // Check for duplicates
        if (queue.some(item => item.url === url)) {
            notifyUser('⚠️ Already in Queue', `"${url}" is already queued for scanning`);
            console.log('URL already in queue:', url);
            return;
        }
        
        // Add to queue
        queue.push({
            url: url,
            addedAt: new Date().toISOString(),
            status: 'pending', // pending, scanning, completed, failed
            uuid: null,
            error: null
        });
        
        await saveUrlScanQueue(queue);
        notifySuccess(`Added to scan queue (${queue.length} URLs)`);
        console.log('Added to URLScan queue:', url);
        
        // Update context menus to show new count
        await createContextMenus();
    } catch (error) {
        console.error('Failed to add to queue:', error);
        notifyError('Queue Error', 'Failed to add URL to scan queue');
    }
}

/**
 * Process URLScan queue
 */
async function processUrlScanQueue() {
    if (isProcessingQueue) {
        notifyUser('⚠️ Already Processing', 'Queue is already being processed');
        return;
    }
    
    const queue = await getUrlScanQueue();
    const pendingItems = queue.filter(item => item.status === 'pending');
    
    if (pendingItems.length === 0) {
        notifyUser('ℹ️ Queue Empty', 'No URLs pending in scan queue');
        return;
    }
    
    isProcessingQueue = true;
    queueProcessCancelled = false;
    
    notifyUser('🚀 Processing Queue', `Starting to scan ${pendingItems.length} URLs...`);
    console.log(`Processing URLScan queue: ${pendingItems.length} URLs`);
    
    let completed = 0;
    let failed = 0;
    
    for (const item of pendingItems) {
        if (queueProcessCancelled) {
            notifyUser('⚠️ Queue Cancelled', 'Queue processing stopped by user');
            break;
        }
        
        // Update status to scanning
        item.status = 'scanning';
        await saveUrlScanQueue(queue);
        
        try {
            console.log(`Scanning ${completed + 1}/${pendingItems.length}: ${item.url}`);
            notifyUser('🔍 Scanning', `Processing ${completed + 1}/${pendingItems.length}: ${item.url.substring(0, 50)}...`);
            
            // Scan the URL
            await sendToUrlscan(item.url, true);
            
            item.status = 'completed';
            completed++;
        } catch (error) {
            console.error('Failed to scan:', item.url, error);
            item.status = 'failed';
            item.error = error.message;
            failed++;
        }
        
        await saveUrlScanQueue(queue);
        
        // Rate limiting: wait 2.5 seconds between scans
        if (completed + failed < pendingItems.length) {
            await new Promise(resolve => setTimeout(resolve, 2500));
        }
    }
    
    isProcessingQueue = false;
    
    // Final notification
    if (failed === 0) {
        notifySuccess(`✓ Queue Complete! Successfully scanned all ${completed} URLs`);
    } else {
        notifyUser('⚠️ Queue Complete', `Scanned ${completed} URLs, ${failed} failed`);
    }
    
    console.log(`Queue processing complete: ${completed} success, ${failed} failed`);
}

/**
 * Clear URLScan queue
 */
async function clearUrlScanQueue() {
    await saveUrlScanQueue([]);
    await createContextMenus(); // Update menu to remove count
    notifySuccess('Queue cleared');
    console.log('URLScan queue cleared');
}

/**
 * Create context menus based on available integrations
 */
async function createContextMenus() {
    try {
        // Remove all existing menus
        await browser.contextMenus.removeAll();
        console.log('Creating context menus...');

        // Contexts where menus should appear: links and selected text
        const contexts = ['link', 'selection'];

        // Create parent "Security" menu
        browser.contextMenus.create({
            id: 'security-parent',
            title: 'Security Analysis',
            contexts: contexts
        });

        // Get queue count for URLScan menu
        const queue = await getUrlScanQueue();
        const pendingCount = queue.filter(item => item.status === 'pending').length;

        // Add URLScan.io parent menu
        browser.contextMenus.create({
            id: 'urlscan-parent',
            parentId: 'security-parent',
            title: 'URLScan.io',
            contexts: ['link'],
            icons: {
                16: 'icons/urlscan_16.png'
            }
        });

        // Add "Scan Now" option
        browser.contextMenus.create({
            id: 'urlscan-submit',
            parentId: 'urlscan-parent',
            title: '🔍 Scan Now',
            contexts: ['link']
        });

        // Add "Add to Queue" option
        browser.contextMenus.create({
            id: 'urlscan-queue-add',
            parentId: 'urlscan-parent',
            title: '➕ Add to Scan Queue',
            contexts: ['link']
        });

        // Add "Process Queue" option (if queue has items)
        if (pendingCount > 0) {
            browser.contextMenus.create({
                id: 'urlscan-queue-separator',
                parentId: 'urlscan-parent',
                type: 'separator',
                contexts: ['link']
            });

            browser.contextMenus.create({
                id: 'urlscan-queue-process',
                parentId: 'urlscan-parent',
                title: `🚀 Process Queue (${pendingCount} URL${pendingCount !== 1 ? 's' : ''})`,
                contexts: ['link']
            });
        }

        // Fetch NextDNS profiles
        nextDnsProfiles = await fetchNextDnsProfiles();
        console.log(`Fetched ${nextDnsProfiles.length} NextDNS profiles`);

        if (nextDnsProfiles.length > 0) {
            // Create NextDNS parent menu
            browser.contextMenus.create({
                id: 'nextdns-parent',
                parentId: 'security-parent',
                title: 'NextDNS',
                contexts: contexts
            });

            // Create "Add to blocklist" submenu
            browser.contextMenus.create({
                id: 'nextdns-blocklist',
                parentId: 'nextdns-parent',
                title: '🚫 Add to Blocklist',
                contexts: contexts
            });

            // Create "Add to allowlist" submenu
            browser.contextMenus.create({
                id: 'nextdns-allowlist',
                parentId: 'nextdns-parent',
                title: '✓ Add to Allowlist',
                contexts: contexts
            });

            // Add profile options for blocklist
            console.log('Creating blocklist profile menus...');
            
            // Add "All Profiles" option first
            if (nextDnsProfiles.length > 1) {
                try {
                    browser.contextMenus.create({
                        id: 'nextdns-blocklist-all',
                        parentId: 'nextdns-blocklist',
                        title: '📋 All Profiles',
                        contexts: contexts
                    });
                    console.log('  ✓ Created "All Profiles" option for blocklist');
                    
                    // Add separator
                    browser.contextMenus.create({
                        id: 'nextdns-blocklist-separator',
                        parentId: 'nextdns-blocklist',
                        type: 'separator',
                        contexts: contexts
                    });
                } catch (err) {
                    console.error('  ✗ Failed to create "All Profiles" menu:', err);
                }
            }
            
            for (const profile of nextDnsProfiles) {
                try {
                    browser.contextMenus.create({
                        id: `nextdns-blocklist-${profile.id}`,
                        parentId: 'nextdns-blocklist',
                        title: profile.name || profile.id,
                        contexts: contexts
                    });
                    console.log(`  ✓ Created blocklist menu for: ${profile.name || profile.id}`);
                } catch (err) {
                    console.error(`  ✗ Failed to create blocklist menu for ${profile.id}:`, err);
                }
            }

            // Add profile options for allowlist
            console.log('Creating allowlist profile menus...');
            
            // Add "All Profiles" option first
            if (nextDnsProfiles.length > 1) {
                try {
                    browser.contextMenus.create({
                        id: 'nextdns-allowlist-all',
                        parentId: 'nextdns-allowlist',
                        title: '📋 All Profiles',
                        contexts: contexts
                    });
                    console.log('  ✓ Created "All Profiles" option for allowlist');
                    
                    // Add separator
                    browser.contextMenus.create({
                        id: 'nextdns-allowlist-separator',
                        parentId: 'nextdns-allowlist',
                        type: 'separator',
                        contexts: contexts
                    });
                } catch (err) {
                    console.error('  ✗ Failed to create "All Profiles" menu:', err);
                }
            }
            
            for (const profile of nextDnsProfiles) {
                try {
                    browser.contextMenus.create({
                        id: `nextdns-allowlist-${profile.id}`,
                        parentId: 'nextdns-allowlist',
                        title: profile.name || profile.id,
                        contexts: contexts
                    });
                    console.log(`  ✓ Created allowlist menu for: ${profile.name || profile.id}`);
                } catch (err) {
                    console.error(`  ✗ Failed to create allowlist menu for ${profile.id}:`, err);
                }
            }

            console.log(`✓ Created NextDNS menus for ${nextDnsProfiles.length} profiles`);
        } else {
            console.log('No NextDNS profiles found (API key may not be configured)');
        }

        // Add separator and future tools hint
        browser.contextMenus.create({
            id: 'separator',
            parentId: 'security-parent',
            type: 'separator',
            contexts: contexts
        });

        browser.contextMenus.create({
            id: 'more-tools',
            parentId: 'security-parent',
            title: '⚙️ Configure Tools',
            contexts: contexts
        });

        console.log('✓ Context menus created successfully');
    } catch (error) {
        console.error('Error creating context menus:', error);
    }
}

/**
 * Handle context menu clicks
 */
browser.contextMenus.onClicked.addListener(async (info) => {
    const menuItemId = info.menuItemId;
    
    // Get URL/domain from either link or selected text
    const linkUrl = info.linkUrl;
    const selectedText = info.selectionText?.trim();
    
    // Determine the target (prefer link over selection)
    const target = linkUrl || selectedText;
    
    if (!target) {
        console.log('No link or selected text found');
        return;
    }

    console.log('Context menu clicked:', {
        menuItemId,
        linkUrl,
        selectedText,
        target
    });

    // URLScan.io - Scan Now
    if (menuItemId === 'urlscan-submit') {
        console.log('Scanning URL:', target);
        sendToUrlscan(target);
    }
    // URLScan.io - Add to Queue
    else if (menuItemId === 'urlscan-queue-add') {
        console.log('Adding to scan queue:', target);
        addToUrlScanQueue(target);
    }
    // URLScan.io - Process Queue
    else if (menuItemId === 'urlscan-queue-process') {
        console.log('Processing scan queue');
        processUrlScanQueue();
    }
    // NextDNS - Add to ALL profiles (blocklist)
    else if (menuItemId === 'nextdns-blocklist-all') {
        const domain = extractDomain(target);
        console.log(`Adding ${domain} to blocklist for ALL profiles`);
        let successCount = 0;
        let failCount = 0;
        
        for (const profile of nextDnsProfiles) {
            try {
                await addToNextDnsList(profile.id, profile.name || profile.id, domain, 'denylist', true);
                successCount++;
            } catch (error) {
                console.error(`Failed to add to profile ${profile.id}:`, error);
                failCount++;
            }
        }
        
        if (successCount === nextDnsProfiles.length) {
            notifySuccess(`NextDNS: Added "${domain}" to blocklist in all ${successCount} profiles`);
        } else if (successCount > 0) {
            notifySuccess(`NextDNS: Added "${domain}" to ${successCount} profiles (${failCount} failed)`);
        } else {
            notifyError('NextDNS Error', `Failed to add "${domain}" to any profiles`);
        }
    }
    // NextDNS - Add to ALL profiles (allowlist)
    else if (menuItemId === 'nextdns-allowlist-all') {
        const domain = extractDomain(target);
        console.log(`Adding ${domain} to allowlist for ALL profiles`);
        let successCount = 0;
        let failCount = 0;
        
        for (const profile of nextDnsProfiles) {
            try {
                await addToNextDnsList(profile.id, profile.name || profile.id, domain, 'allowlist', true);
                successCount++;
            } catch (error) {
                console.error(`Failed to add to profile ${profile.id}:`, error);
                failCount++;
            }
        }
        
        if (successCount === nextDnsProfiles.length) {
            notifySuccess(`NextDNS: Added "${domain}" to allowlist in all ${successCount} profiles`);
        } else if (successCount > 0) {
            notifySuccess(`NextDNS: Added "${domain}" to ${successCount} profiles (${failCount} failed)`);
        } else {
            notifyError('NextDNS Error', `Failed to add "${domain}" to any profiles`);
        }
    }
    // NextDNS blocklist (single profile)
    else if (menuItemId.startsWith('nextdns-blocklist-')) {
        const profileId = menuItemId.replace('nextdns-blocklist-', '');
        const profile = nextDnsProfiles.find(p => p.id === profileId);
        const domain = extractDomain(target);
        console.log(`Adding ${domain} to blocklist for profile ${profileId}`);
        addToNextDnsList(profileId, profile?.name || profileId, domain, 'denylist');
    }
    // NextDNS allowlist (single profile)
    else if (menuItemId.startsWith('nextdns-allowlist-')) {
        const profileId = menuItemId.replace('nextdns-allowlist-', '');
        const profile = nextDnsProfiles.find(p => p.id === profileId);
        const domain = extractDomain(target);
        console.log(`Adding ${domain} to allowlist for profile ${profileId}`);
        addToNextDnsList(profileId, profile?.name || profileId, domain, 'allowlist');
    }
    // Configure tools
    else if (menuItemId === 'more-tools') {
        browser.runtime.openOptionsPage();
    }
});

/**
 * Display a browser notification to the user
 * @param {string} title - Notification title
 * @param {string} message - Notification message
 */
function notifyUser(title, message) {
    browser.notifications.create({
        type: 'basic',
        iconUrl: 'icons/urlscan_32.png',
        title,
        message,
        priority: 2
    });
}

/**
 * Display a success notification
 * @param {string} message - Success message
 */
function notifySuccess(message) {
    notifyUser('✓ Success', message);
}

/**
 * Display an error notification
 * @param {string} title - Error title
 * @param {string} message - Error message
 */
function notifyError(title, message) {
    notifyUser(`✗ ${title}`, message);
}

// ---- Message Handling for Options Page ----
// Handle messages from options page (for testing API connection)
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'testNextDnsConnection') {
        // Test NextDNS API connection
        (async () => {
            try {
                const apiKey = message.apiKey;
                if (!apiKey) {
                    sendResponse({ success: false, error: 'No API key provided' });
                    return;
                }

                const response = await fetch('https://api.nextdns.io/profiles', {
                    headers: { 'X-Api-Key': apiKey }
                });

                if (response.ok) {
                    const data = await response.json();
                    const profiles = data.data || [];
                    sendResponse({ 
                        success: true, 
                        profiles: profiles,
                        count: profiles.length 
                    });
                } else {
                    const errorText = await response.text().catch(() => 'Unknown error');
                    sendResponse({ 
                        success: false, 
                        error: `HTTP ${response.status}: ${errorText}`,
                        status: response.status
                    });
                }
            } catch (error) {
                sendResponse({ 
                    success: false, 
                    error: error.message 
                });
            }
        })();
        return true; // Keep message channel open for async response
    }
    
    if (message.action === 'fetchProfiles') {
        // Fetch profiles and rebuild menus
        (async () => {
            await createContextMenus();
            sendResponse({ success: true });
        })();
        return true;
    }
    
    if (message.action === 'getUrlScanQueue') {
        // Get URLScan queue
        (async () => {
            const queue = await getUrlScanQueue();
            sendResponse({ success: true, queue: queue });
        })();
        return true;
    }
    
    if (message.action === 'removeFromQueue') {
        // Remove item from queue
        (async () => {
            const queue = await getUrlScanQueue();
            const filtered = queue.filter(item => item.url !== message.url);
            await saveUrlScanQueue(filtered);
            await createContextMenus(); // Update menu count
            sendResponse({ success: true });
        })();
        return true;
    }
    
    if (message.action === 'clearQueue') {
        // Clear queue
        (async () => {
            await clearUrlScanQueue();
            sendResponse({ success: true });
        })();
        return true;
    }
    
    if (message.action === 'processQueue') {
        // Process queue
        (async () => {
            processUrlScanQueue();
            sendResponse({ success: true });
        })();
        return true;
    }
    
    if (message.action === 'cancelQueueProcessing') {
        // Cancel queue processing
        queueProcessCancelled = true;
        sendResponse({ success: true });
        return true;
    }
});

// ---- Extension Initialization ----
// Create context menus on extension load
createContextMenus();

// Listen for storage changes to update menus dynamically
browser.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'sync') {
        // Recreate menus if any relevant setting changed
        if (changes.nextdnsApiKey || changes.urlscanApiKey) {
            console.log('Settings changed, recreating menus...');
            // Small delay to ensure storage is updated
            setTimeout(() => {
                createContextMenus();
            }, 500);
        }
    }
});

console.log('Security Analysis extension loaded successfully');