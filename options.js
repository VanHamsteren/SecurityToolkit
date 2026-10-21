/* global browser, Busy */
/**
 * Security Toolkit - settings page
 * Every action that waits for a network answer goes through Busy.run, which
 * disables the button and shows a spinner, so a second click cannot happen.
 */

const DEFAULTS = {
    tags: "firefox, extension",
    visibility: "unlisted",
    notificationLevel: "errors",
    qsLiveMode: "ask",
    qsFollowClient: true,
};

const QS_LIVE_PERMISSIONS = {
    permissions: ["webRequest", "webRequestBlocking"],
    origins: ["<all_urls>"],
};

const $ = (id) => document.getElementById(id);
const form = $("settingsForm");
const apiKeyInput = $("apiKey");
const visibilitySelect = $("visibility");
const tagsInput = $("tags");
const nextdnsApiKeyInput = $("nextdnsApiKey");
const vtApiKeyInput = $("vtApiKey");
const abuseIpdbApiKeyInput = $("abuseIpdbApiKey");
const notificationLevelSelect = $("notificationLevel");
const saveButton = $("save");
const resetButton = $("reset");
const qsLiveModeSelect = $("qsLiveMode");
const qsFollowClientCheckbox = $("qsFollowClient");
const qsGrantBtn = $("qsGrant");
const qsPermState = $("qsPermState");
const statusDiv = $("status");
const apiKeyError = $("apiKeyError");
const nextdnsKeyError = $("nextdnsKeyError");
const profilesInfo = $("profilesInfo");
const profilesList = $("profilesList");

let statusTimer;

function validateApiKey(apiKey) {
    return apiKey.trim().length >= 20;
}

/**
 * Show a message. With an anchor (a button) the message appears right below that button,
 * inside the section it belongs to; without one it appears next to the Save button.
 */
function showStatus(message, isSuccess, anchor) {
    let target = statusDiv;
    if (anchor) {
        target = anchor.nextElementSibling?.classList.contains("inline-status") ? anchor.nextElementSibling : null;
        if (!target) {
            target = document.createElement("div");
            target.className = "inline-status";
            target.setAttribute("role", "status");
            anchor.after(target);
        }
    }
    target.textContent = message;
    target.className = `${anchor ? "inline-status " : ""}show ${isSuccess ? "success" : "error"}`;
    if (!anchor) {
        statusDiv.setAttribute("data-testid", isSuccess ? "status-success" : "status-error");
        clearTimeout(statusTimer);
        statusTimer = setTimeout(() => statusDiv.classList.remove("show"), 8000);
    }
}

function showFieldError(input, errorElement, show) {
    input.classList.toggle("error", show);
    errorElement.classList.toggle("show", show);
}

function renderProfiles(profiles) {
    profilesList.replaceChildren(...profiles.map((p) => {
        const li = document.createElement("li");
        li.textContent = `${p.name || p.id} (${p.id})`;
        return li;
    }));
    profilesInfo.classList.add("show");
}

/** Fetch and show NextDNS profiles via the background script */
async function fetchAndDisplayProfiles() {
    const apiKey = nextdnsApiKeyInput.value.trim();
    if (!apiKey) {
        profilesInfo.classList.remove("show");
        return;
    }
    try {
        const response = await browser.runtime.sendMessage({ action: "testNextDnsConnection", apiKey });
        if (response?.success && response.profiles.length > 0) renderProfiles(response.profiles);
        else profilesInfo.classList.remove("show");
    } catch (error) {
        console.error("Error fetching profiles via background:", error);
        profilesInfo.classList.remove("show");
    }
}

// Show / hide key buttons
function wireToggle(button, input) {
    button.addEventListener("click", () => {
        const hidden = input.type === "password";
        input.type = hidden ? "text" : "password";
        button.textContent = hidden ? "Hide" : "Show";
    });
}
wireToggle($("toggleApiKey"), apiKeyInput);
wireToggle($("toggleNextDnsKey"), nextdnsApiKeyInput);
wireToggle($("toggleVtKey"), vtApiKeyInput);
wireToggle($("toggleAbuseKey"), abuseIpdbApiKeyInput);

/**
 * Test a connection through the background script.
 * Optional host permission is requested first (it must be the first await in the click handler).
 */
function wireTest(button, input, action, serviceName, origin) {
    button.addEventListener("click", async () => {
        if (button.getAttribute("aria-busy") === "true") return;
        if (!input.value.trim()) {
            showStatus(`Please enter a ${serviceName} API key first.`, false, button);
            input.focus();
            return;
        }
        if (origin) {
            try {
                const granted = await browser.permissions.request({ origins: [origin] });
                if (!granted) {
                    showStatus(`${serviceName} needs permission to be contacted. Choose Allow in the prompt, or grant it under about:addons > Security Toolkit > Permissions.`, false, button);
                    return;
                }
            } catch (error) {
                console.error("Permission request failed:", error);
            }
        }
        await Busy.run(button, "Testing...", async () => {
            try {
                const response = await browser.runtime.sendMessage({ action, apiKey: input.value.trim() });
                if (!response) {
                    showStatus("No response from the extension background. Reload the extension in about:debugging and try again.", false, button);
                    return;
                }
                if (response.success) {
                    if (response.profiles) {
                        if (response.profiles.length) {
                            renderProfiles(response.profiles);
                            showStatus(`${serviceName} connection works. Found ${response.profiles.length} profile(s): ${response.profiles.map((p) => p.name || p.id).join(", ")}`, true, button);
                        } else {
                            showStatus("Connection works but no profiles were found. Create a profile at nextdns.io.", false, button);
                        }
                    } else {
                        showStatus(`${serviceName} connection works.${response.quotaInfo ? ` (${response.quotaInfo})` : ""}`, true, button);
                    }
                } else {
                    showStatus(`${serviceName} connection failed: ${response.error}. Check your API key.`, false, button);
                }
            } catch (error) {
                showStatus(`Error: ${error.message}`, false, button);
                console.error(`${serviceName} connection error:`, error);
            }
        });
    });
}

wireTest($("testUrlscan"), apiKeyInput, "testUrlscanConnection", "urlscan.io", null);
wireTest($("testVt"), vtApiKeyInput, "testVirusTotalConnection", "VirusTotal", "https://www.virustotal.com/*");
wireTest($("testAbuse"), abuseIpdbApiKeyInput, "testAbuseIpdbConnection", "AbuseIPDB", "https://api.abuseipdb.com/*");
wireTest($("testNextDns"), nextdnsApiKeyInput, "testNextDnsConnection", "NextDNS", null);

// Save
form.addEventListener("submit", (e) => {
    e.preventDefault();
    const apiKey = apiKeyInput.value.trim();
    const nextdnsApiKey = nextdnsApiKeyInput.value.trim();
    const vtApiKey = vtApiKeyInput.value.trim();
    const abuseIpdbApiKey = abuseIpdbApiKeyInput.value.trim();
    const tags = tagsInput.value.trim();

    apiKeyInput.value = apiKey;
    nextdnsApiKeyInput.value = nextdnsApiKey;
    vtApiKeyInput.value = vtApiKey;
    abuseIpdbApiKeyInput.value = abuseIpdbApiKey;

    if (apiKey && !validateApiKey(apiKey)) {
        showFieldError(apiKeyInput, apiKeyError, true);
        showStatus("Please enter a valid urlscan.io API key (minimum 20 characters).", false);
        apiKeyInput.focus();
        return;
    }
    showFieldError(apiKeyInput, apiKeyError, false);
    showFieldError(nextdnsApiKeyInput, nextdnsKeyError, false);

    Busy.run(saveButton, "Saving...", async () => {
        try {
            await browser.storage.sync.set({
                urlscanApiKey: apiKey,
                urlscanVisibility: visibilitySelect.value,
                urlscanTags: tags || DEFAULTS.tags,
                nextdnsApiKey,
                vtApiKey,
                abuseIpdbApiKey,
                notificationLevel: notificationLevelSelect.value,
                qsLiveMode: qsLiveModeSelect.value,
                qsFollowClient: qsFollowClientCheckbox.checked,
            });
            showStatus("Settings saved. The context menu will update shortly.", true);
            if (nextdnsApiKey) await fetchAndDisplayProfiles();
            else profilesInfo.classList.remove("show");
        } catch (error) {
            console.error("Storage error:", error);
            showStatus("Could not save the settings. Please try again.", false);
        }
    });
});

resetButton.addEventListener("click", () => {
    if (!confirm("Reset all settings to their defaults? Your API keys are kept.")) return;
    visibilitySelect.value = DEFAULTS.visibility;
    tagsInput.value = DEFAULTS.tags;
    notificationLevelSelect.value = DEFAULTS.notificationLevel;
    qsLiveModeSelect.value = DEFAULTS.qsLiveMode;
    qsFollowClientCheckbox.checked = DEFAULTS.qsFollowClient;
    showStatus("Settings reset. Choose Save to apply.", true);
});

apiKeyInput.addEventListener("input", () => {
    const value = apiKeyInput.value.trim();
    showFieldError(apiKeyInput, apiKeyError, value.length > 0 && !validateApiKey(value));
});

let fetchTimeout;
nextdnsApiKeyInput.addEventListener("input", () => {
    clearTimeout(fetchTimeout);
    fetchTimeout = setTimeout(fetchAndDisplayProfiles, 1000);
});

// Quick Scan live-fetch permission
async function updateQsPermState() {
    try {
        if (await browser.permissions.contains(QS_LIVE_PERMISSIONS)) {
            qsPermState.textContent = "Live-fetch permissions granted. You can revoke them any time under about:addons > Security Toolkit > Permissions.";
            qsGrantBtn.hidden = true;
        }
    } catch (error) {
        console.error("Permission check failed:", error);
    }
}

qsGrantBtn.addEventListener("click", async () => {
    try {
        const granted = await browser.permissions.request(QS_LIVE_PERMISSIONS); // first await: keeps the user gesture
        if (!granted) showStatus("Live fetch stays disabled. The offline Quick Scan still works.", false, qsGrantBtn);
    } catch (error) {
        console.error("Permission request failed:", error);
    }
    updateQsPermState();
});

// Scan queue: only a summary here, the work happens on the queue page
async function loadQueueCount() {
    try {
        const response = await browser.runtime.sendMessage({ action: "getUrlScanQueue" });
        if (response?.success) $("queueCount").textContent = response.queue.filter((i) => i.status === "pending").length;
    } catch (error) {
        console.error("Failed to load queue:", error);
    }
}

$("openQueue").addEventListener("click", () => {
    browser.tabs.create({ url: browser.runtime.getURL("report.html?queue=1"), active: true });
});

// Load saved settings
document.addEventListener("DOMContentLoaded", async () => {
    try {
        const result = await browser.storage.sync.get([
            "urlscanApiKey", "urlscanVisibility", "urlscanTags", "nextdnsApiKey", "vtApiKey",
            "abuseIpdbApiKey", "notificationLevel", "qsLiveMode", "qsFollowClient",
        ]);
        apiKeyInput.value = result.urlscanApiKey || "";
        visibilitySelect.value = result.urlscanVisibility || DEFAULTS.visibility;
        tagsInput.value = result.urlscanTags || DEFAULTS.tags;
        vtApiKeyInput.value = result.vtApiKey || "";
        abuseIpdbApiKeyInput.value = result.abuseIpdbApiKey || "";
        notificationLevelSelect.value = result.notificationLevel || DEFAULTS.notificationLevel;
        qsLiveModeSelect.value = result.qsLiveMode || DEFAULTS.qsLiveMode;
        qsFollowClientCheckbox.checked = result.qsFollowClient ?? DEFAULTS.qsFollowClient;
        updateQsPermState();
        loadQueueCount();
        if (result.nextdnsApiKey) {
            nextdnsApiKeyInput.value = result.nextdnsApiKey;
            await fetchAndDisplayProfiles();
        }
    } catch (error) {
        console.error("Error loading settings:", error);
        showStatus("Could not load the saved settings.", false);
    }
});
