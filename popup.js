/* global browser, Busy */
/**
 * Toolbar popup: queue overview and shortcuts.
 * Scanning and results live on the queue page, so this popup only opens it.
 */

const totalCount = document.getElementById("totalCount");
const pendingCount = document.getElementById("pendingCount");
const completedCount = document.getElementById("completedCount");
const processQueueBtn = document.getElementById("processQueue");
const viewQueueBtn = document.getElementById("viewQueue");
const clearQueueBtn = document.getElementById("clearQueue");
const emptyState = document.getElementById("emptyState");
const queueActions = document.getElementById("queueActions");
const processingIndicator = document.getElementById("processingIndicator");

const openPage = (path) => {
    browser.tabs.create({ url: browser.runtime.getURL(path), active: true });
    window.close();
};

async function loadQueueStats() {
    try {
        const response = await browser.runtime.sendMessage({ action: "getUrlScanQueue" });
        if (!response?.success) return;
        const queue = response.queue;
        const pendingReal = queue.filter((i) => i.status === "pending").length;
        const completed = queue.filter((i) => i.status === "completed").length;
        const { urlscanHeartbeat = 0 } = await browser.storage.local.get("urlscanHeartbeat");
        const live = Date.now() - urlscanHeartbeat < 15000; // the queue page is really scanning
        const stale = queue.filter((i) => i.status === "scanning").length;
        const scanning = live ? stale : 0;
        const pending = pendingReal + (live ? 0 : stale); // interrupted links count as waiting

        totalCount.textContent = queue.length;
        pendingCount.textContent = pending;
        completedCount.textContent = completed;

        emptyState.hidden = queue.length !== 0;
        queueActions.hidden = queue.length === 0;
        if (!clearQueueBtn.hasAttribute("aria-busy")) {
            processQueueBtn.disabled = pending === 0;
            clearQueueBtn.disabled = queue.length === 0;
        }
        processingIndicator.hidden = scanning === 0;
    } catch (error) {
        console.error("Failed to load queue stats:", error);
    }
}

// The queue page asks for permission and shows progress, so the popup just opens it
processQueueBtn.addEventListener("click", () => openPage("report.html?queue=1&autostart=1"));
viewQueueBtn.addEventListener("click", () => openPage("report.html?queue=1"));

clearQueueBtn.addEventListener("click", () => {
    if (!confirm("Clear the entire scan queue?")) return;
    Busy.run(clearQueueBtn, "Clearing...", async () => {
        await browser.runtime.sendMessage({ action: "clearQueue" });
        await loadQueueStats();
    });
});

document.getElementById("openQuickScans").addEventListener("click", () => openPage("report.html"));
document.getElementById("openSettings").addEventListener("click", () => {
    browser.runtime.openOptionsPage();
    window.close();
});

loadQueueStats();
setInterval(loadQueueStats, 3000);

// The version comes from the manifest, so it can never be out of date
document.getElementById("version").textContent = `v${browser.runtime.getManifest().version}`;
