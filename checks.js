/* global browser */
/**
 * Security Toolkit - reputation checks (urlscan.io, VirusTotal, AbuseIPDB)
 *
 * Runs inside the report page (an extension page, so it has the same host
 * permissions as the background script). Every tool returns the same summary
 * shape, so the report can show them side by side and combine them:
 *
 *   { tool, status: "done" | "error", level: "clean"|"low"|"medium"|"high"|"unknown",
 *     headline, details: [[label, value]], link: {href, label}, screenshot?, note?, finishedAt }
 *
 * Results are saved under their own storage key (ck_<reportId>) so they never
 * race with the Quick Scan engine, which owns qs_<reportId>.
 *
 * All strings that come from third parties are shown with textContent only.
 */

const CK = {
    TOOLS: ["urlscan", "virustotal", "abuseipdb"],
    NAMES: { urlscan: "urlscan.io", virustotal: "VirusTotal", abuseipdb: "AbuseIPDB" },
    KEYS: { urlscan: "urlscanApiKey", virustotal: "vtApiKey", abuseipdb: "abuseIpdbApiKey" },
    ORIGINS: {
        urlscan: ["https://urlscan.io/*"],
        virustotal: ["https://www.virustotal.com/*"],
        abuseipdb: ["https://api.abuseipdb.com/*"],
    },
    PREFIX: "ck_",
    RANK: { unknown: -1, clean: 0, low: 1, medium: 2, high: 3 },
    // Polling rhythm. VirusTotal's free tier allows 4 requests a minute, so it polls slowly.
    timing: {
        urlscanFirst: 8000, urlscanEvery: 3000, urlscanMax: 120000,
        vtFirst: 10000, vtEvery: 16000, vtMax: 240000, vtRetry: 20000,
    },
};

class CkError extends Error {
    constructor(message, hint) {
        super(message);
        this.hint = hint || "";
    }
}

const ckSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ---------------------------------------------------------------------------
// Configuration and permissions
// ---------------------------------------------------------------------------

async function ckConfig() {
    return browser.storage.sync.get([
        "urlscanApiKey", "urlscanVisibility", "urlscanTags", "vtApiKey", "abuseIpdbApiKey",
    ]);
}

function ckIsConfigured(cfg, tool) {
    const key = cfg[CK.KEYS[tool]];
    return typeof key === "string" && key.trim().length > 0;
}

async function ckHasPermission(tool) {
    try {
        return await browser.permissions.contains({ origins: CK.ORIGINS[tool] });
    } catch {
        return false;
    }
}

/**
 * Ask for the host permissions of the given tools in ONE prompt.
 * Must be the first await inside a click handler (Firefox needs the user gesture).
 */
function ckRequestPermissions(tools) {
    const origins = [...new Set(tools.flatMap((t) => CK.ORIGINS[t]))];
    return browser.permissions.request({ origins });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ckExplainNetworkError(tool, error) {
    if (error instanceof CkError) return error;
    if (error instanceof TypeError) {
        return new CkError(
            `Could not reach ${CK.NAMES[tool]}.`,
            "Check your connection. If this is the first time, the extension may not have permission for this site yet: use Allow and run.",
        );
    }
    return new CkError(error?.message || "Unexpected error");
}

function ckBase64Url(text) {
    const bytes = new TextEncoder().encode(text);
    let bin = "";
    bytes.forEach((b) => {
        bin += String.fromCharCode(b);
    });
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function ckNormalizeUrl(input) {
    return /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
}

function ckIsIp(host) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(host);
}

function ckDone(tool, level, headline, details, extra = {}) {
    return { tool, status: "done", level, headline, details: details.filter(([, v]) => v !== undefined && v !== null && v !== ""), finishedAt: new Date().toISOString(), ...extra };
}

// ---------------------------------------------------------------------------
// urlscan.io
// ---------------------------------------------------------------------------

/**
 * Every domain urlscan.io saw while loading the page, as a tree: the first host is the root,
 * each other host hangs under the host that redirected to it or loaded it.
 */
function ckUrlscanChain(data) {
    const hostOf = (u) => {
        try {
            return new URL(u).hostname.toLowerCase();
        } catch {
            return "";
        }
    };
    const nodes = new Map();
    let root = "";
    for (const entry of data?.data?.requests || []) {
        const rq = entry?.request || {};
        const host = hostOf(rq.request?.url);
        if (!host) continue;
        const seen = nodes.get(host);
        if (seen) {
            seen.count++;
            continue;
        }
        if (nodes.size >= 150) continue;
        if (!root) root = host;
        const redirected = Boolean(rq.redirectResponse?.url);
        let parent = hostOf(redirected ? rq.redirectResponse.url : (rq.initiator?.url || rq.documentURL));
        // a parent must already be in the tree, which also rules out loops
        if (host === root) parent = "";
        else if (!parent || parent === host || !nodes.has(parent)) parent = root;
        nodes.set(host, {
            domain: host, parent, via: redirected ? "redirect" : "load", count: 1,
            ip: entry?.response?.response?.remoteIPAddress || entry?.response?.asn?.ip || "",
        });
    }
    return [...nodes.values()];
}

function ckParseUrlscan(uuid, data) {
    const overall = data?.verdicts?.overall || {};
    const us = data?.verdicts?.urlscan || {};
    const page = data?.page || {};
    const score = typeof overall.score === "number" ? overall.score : (us.score || 0);
    const malicious = Boolean(overall.malicious || us.malicious);
    const categories = [...new Set([...(overall.categories || []), ...(us.categories || [])])];
    const brands = (us.brands || []).map((b) => b.name || b.key).filter(Boolean);
    const hasVerdict = Boolean(overall.hasVerdicts || us.hasVerdicts);

    let level = "unknown";
    let headline = "No verdict available";
    if (malicious) {
        level = "high";
        headline = "Flagged as malicious";
    } else if (score > 0 || categories.length || brands.length) {
        level = "medium";
        headline = "Some suspicious indicators";
    } else if (hasVerdict) {
        level = "clean";
        headline = "No malicious verdict";
    }
    const requests = data?.lists?.urls?.length;
    const chain = ckUrlscanChain(data);
    return ckDone("urlscan", level, headline, [
        ["Final URL", page.url],
        ["Server IP", page.ip],
        ["Country", page.country],
        ["Network", [page.asn, page.asnname].filter(Boolean).join(" ")],
        ["Server", page.server],
        ["Page title", page.title],
        ["Impersonated brands", brands.join(", ")],
        ["Categories", categories.join(", ")],
        ["Requests made", requests],
        ["Domains contacted", chain.length || ""],
    ], {
        chain,
        link: { href: `https://urlscan.io/result/${uuid}/`, label: "Open the urlscan.io report" },
        screenshot: `https://urlscan.io/screenshots/${uuid}.png`,
    });
}

/** Submit a URL to urlscan.io and return its scan id */
async function ckUrlscanSubmit(url, cfg) {
    const tags = (cfg.urlscanTags || "").split(",").map((t) => t.trim()).filter(Boolean);
    const res = await fetch("https://urlscan.io/api/v1/scan/", {
        method: "POST",
        headers: { "Content-Type": "application/json", "API-Key": cfg.urlscanApiKey },
        body: JSON.stringify({
            url,
            visibility: cfg.urlscanVisibility || "unlisted",
            tags: tags.length ? tags : ["firefox", "extension"],
        }),
    });
    if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const hints = {
            401: "The urlscan.io API key was rejected. Check it in the settings.",
            429: "urlscan.io rate limit reached. Wait a minute and try again.",
        };
        throw new CkError(body.description || body.message || `urlscan.io answered HTTP ${res.status}`, hints[res.status]);
    }
    const data = await res.json();
    if (!data.uuid) throw new CkError("urlscan.io did not return a scan id.");
    return data.uuid;
}

/** Wait for a urlscan.io scan to finish and return the summary */
async function ckUrlscanWait(uuid, cfg, onUpdate) {
    const t = CK.timing;
    const started = Date.now();
    await ckSleep(t.urlscanFirst);
    for (;;) {
        const res = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, { headers: { "API-Key": cfg.urlscanApiKey } });
        if (res.ok) return ckParseUrlscan(uuid, await res.json());
        if (res.status !== 404 && res.status !== 410) {
            throw new CkError(`urlscan.io answered HTTP ${res.status} while waiting for the result.`);
        }
        const waited = Date.now() - started;
        if (waited > t.urlscanMax) {
            throw new CkError("urlscan.io is taking longer than expected.", "The scan may still finish. Open it on urlscan.io.");
        }
        if (onUpdate) onUpdate({ note: `urlscan.io is still scanning (${Math.round(waited / 1000)}s)...` });
        await ckSleep(t.urlscanEvery);
    }
}

/** One poll of a urlscan.io result: the summary when ready, null while it is still scanning */
async function ckUrlscanFetchOnce(uuid, cfg) {
    const res = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, { headers: { "API-Key": cfg.urlscanApiKey } });
    if (res.ok) return ckParseUrlscan(uuid, await res.json());
    if (res.status === 404 || res.status === 410) return null;
    throw new CkError(`urlscan.io answered HTTP ${res.status} while waiting for the result.`);
}

async function ckUrlscan(ctx, cfg, onUpdate) {
    const uuid = await ckUrlscanSubmit(ctx.url, cfg);
    onUpdate({
        note: "Submitted. urlscan.io is loading the page from its own servers (usually 10 to 30 seconds).",
        link: { href: `https://urlscan.io/result/${uuid}/`, label: "Open the urlscan.io report" },
    });
    return ckUrlscanWait(uuid, cfg, onUpdate);
}

// ---------------------------------------------------------------------------
// VirusTotal
// ---------------------------------------------------------------------------

function ckParseVirusTotal(analysis, url) {
    const attr = analysis?.data?.attributes || {};
    const stats = attr.stats || {};
    const mal = stats.malicious || 0;
    const sus = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + (Number(b) || 0), 0);

    let level = "unknown";
    if (total > 0) level = mal >= 5 ? "high" : mal >= 1 || sus >= 1 ? "medium" : "clean";
    const headline = total === 0
        ? "No results yet"
        : mal || sus
            ? `${mal} of ${total} engines say malicious${sus ? `, ${sus} suspicious` : ""}`
            : `0 of ${total} engines flag this URL`;

    const flagged = Object.values(attr.results || {})
        .filter((r) => r.category === "malicious" || r.category === "suspicious")
        .slice(0, 8)
        .map((r) => `${r.engine_name || r.engine}: ${r.result || r.category}`);

    const id = analysis?.meta?.url_info?.id;
    return ckDone("virustotal", level, headline, [
        ["Flagged by", flagged.join("\n")],
        ["Harmless / undetected", total ? `${stats.harmless || 0} / ${stats.undetected || 0}` : ""],
    ], {
        link: {
            href: id ? `https://www.virustotal.com/gui/url/${id}` : `https://www.virustotal.com/gui/search/${encodeURIComponent(url)}`,
            label: "Open the VirusTotal report",
        },
    });
}

async function ckVirusTotal(ctx, cfg, onUpdate) {
    const t = CK.timing;
    const headers = { "x-apikey": cfg.vtApiKey };
    const submit = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
        body: `url=${encodeURIComponent(ckNormalizeUrl(ctx.url))}`,
    });
    if (!submit.ok) {
        const body = await submit.json().catch(() => ({}));
        const hints = {
            401: "The VirusTotal API key was rejected. Check it in the settings.",
            429: "VirusTotal rate limit reached (the free tier allows 4 requests a minute). Wait a minute and try again.",
        };
        throw new CkError(body.error?.message || `VirusTotal answered HTTP ${submit.status}`, hints[submit.status]);
    }
    const analysisId = (await submit.json()).data?.id;
    if (!analysisId) throw new CkError("VirusTotal did not return an analysis id.");
    onUpdate({ note: "Submitted. About 70 engines are checking the URL. This usually takes under a minute." });

    const started = Date.now();
    await ckSleep(t.vtFirst);
    for (;;) {
        const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers });
        if (res.status === 429) {
            await ckSleep(t.vtRetry);
        } else if (!res.ok) {
            throw new CkError(`VirusTotal answered HTTP ${res.status} while waiting for the result.`);
        } else {
            const data = await res.json();
            if (data.data?.attributes?.status === "completed") return ckParseVirusTotal(data, ctx.url);
            const waited = Date.now() - started;
            if (waited > t.vtMax) {
                const partial = ckParseVirusTotal(data, ctx.url);
                partial.note = "VirusTotal had not finished after four minutes. These are partial results.";
                return partial;
            }
            onUpdate({ note: `VirusTotal is still analysing (${Math.round(waited / 1000)}s)...` });
        }
        await ckSleep(t.vtEvery);
    }
}

// ---------------------------------------------------------------------------
// AbuseIPDB
// ---------------------------------------------------------------------------

async function ckResolveIp(host) {
    for (const type of ["A", "AAAA"]) {
        try {
            const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=${type}`);
            if (!res.ok) continue;
            const answer = (await res.json()).Answer?.find((a) => a.type === (type === "A" ? 1 : 28));
            if (answer?.data) return answer.data;
        } catch {
            /* try the next record type */
        }
    }
    return null;
}

function ckParseAbuseIpdb(ip, data) {
    const score = data?.abuseConfidenceScore ?? 0;
    const reports = data?.totalReports ?? 0;
    const level = score >= 75 ? "high" : score >= 25 ? "medium" : score > 0 ? "low" : "clean";
    return ckDone("abuseipdb", level,
        `Abuse confidence ${score}% (${reports} report${reports === 1 ? "" : "s"} in 90 days)`, [
            ["Server IP", ip],
            ["Reported by", data?.numDistinctUsers ? `${data.numDistinctUsers} different users` : ""],
            ["Provider", data?.isp],
            ["Usage", data?.usageType],
            ["Country", data?.countryCode],
            ["Tor exit node", data?.isTor ? "yes" : ""],
        ], {
            link: { href: `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`, label: "Open the AbuseIPDB report (you can report the IP there)" },
            note: "AbuseIPDB rates the server's IP address, not the link itself. Shared hosting and CDNs can look cleaner or worse than the link deserves.",
        });
}

async function ckAbuseIpdb(ctx, cfg, onUpdate) {
    let ip = ctx.ip;
    if (!ip && ckIsIp(ctx.host)) ip = ctx.host;
    if (!ip) {
        onUpdate({ note: "Looking up the server IP address..." });
        ip = await ckResolveIp(ctx.host);
    }
    if (!ip) throw new CkError(`Could not resolve ${ctx.host} to an IP address.`, "The domain may not exist (anymore).");
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
        headers: { Key: cfg.abuseIpdbApiKey, Accept: "application/json" },
    });
    if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const hints = {
            401: "The AbuseIPDB API key was rejected. Check it in the settings.",
            429: "AbuseIPDB daily limit reached.",
        };
        throw new CkError(body.errors?.[0]?.detail || `AbuseIPDB answered HTTP ${res.status}`, hints[res.status]);
    }
    return ckParseAbuseIpdb(ip, (await res.json()).data);
}

// ---------------------------------------------------------------------------
// Domain age (from the Quick Scan RDAP lookup, no extra request)
// ---------------------------------------------------------------------------

function ckDomainAge(report) {
    const host = report?.url?.host;
    const rdap = host ? report.hosts?.[host]?.rdap : null;
    if (!rdap) return null;
    if (rdap.found === false) {
        return ckDone("rdap", "unknown", "No registration record found", [["Domain", report.url.apex || host]],
            { note: "Some registries do not publish RDAP data. That says nothing about the domain." });
    }
    const days = rdap.ageDays;
    const level = days == null ? "unknown" : days < 30 ? "high" : days < 180 ? "medium" : "clean";
    const age = days == null ? "" : days < 60 ? `${days} days` : days < 730 ? `${Math.round(days / 30)} months` : `${(days / 365).toFixed(1)} years`;
    return ckDone("rdap", level,
        days == null ? "Registration date unknown" : `Registered ${age} ago`, [
            ["Registered", rdap.registered ? String(rdap.registered).slice(0, 10) : ""],
            ["Registrar", rdap.registrar],
            ["Domain", report.url.apex || host],
        ], {
            note: days != null && days < 180 ? "Recently registered domains are a common phishing signal." : "",
        });
}

// ---------------------------------------------------------------------------
// Running tools
// ---------------------------------------------------------------------------

const CK_RUNNERS = { urlscan: ckUrlscan, virustotal: ckVirusTotal, abuseipdb: ckAbuseIpdb };

/**
 * Run one tool. onUpdate receives partial state ({note, link}) while it works.
 * Never throws: failures come back as { status: "error", error, hint }.
 */
async function ckRunTool(tool, ctx, cfg, onUpdate = () => {}) {
    try {
        return await CK_RUNNERS[tool](ctx, cfg, onUpdate);
    } catch (e) {
        const err = ckExplainNetworkError(tool, e);
        return { tool, status: "error", error: err.message, hint: err.hint, finishedAt: new Date().toISOString() };
    }
}

// ---------------------------------------------------------------------------
// Combined assessment
// ---------------------------------------------------------------------------

function ckOverall(report, tools) {
    const qs = report?.verdict || { level: "clean", score: 0 };
    const done = CK.TOOLS.map((t) => tools?.[t]).filter((r) => r && r.status === "done");
    let rank = CK.RANK[qs.level] ?? 0;
    for (const r of done) rank = Math.max(rank, CK.RANK[r.level] ?? -1);
    const level = Object.keys(CK.RANK).find((k) => CK.RANK[k] === rank && k !== "unknown") || "clean";
    const label = { high: "Malicious indicators", medium: "Suspicious", low: "Some risk signals", clean: "No strong signals" }[level];
    const flagged = done.filter((r) => r.level === "medium" || r.level === "high");
    const summary = [`Quick Scan ${qs.score}/100`, ...done.map((r) => `${CK.NAMES[r.tool]}: ${r.headline}`)];
    return { level, label, flagged: flagged.length, checked: done.length, summary };
}

// ---------------------------------------------------------------------------
// Persistence (separate key from the Quick Scan report)
// ---------------------------------------------------------------------------

let ckWrites = Promise.resolve();

async function ckLoad(id) {
    const key = CK.PREFIX + id;
    const stored = await browser.storage.local.get(key);
    return stored[key]?.tools || {};
}

/** Save one tool's state. Writes are queued so parallel tools cannot overwrite each other. */
function ckSetTool(id, tool, state) {
    ckWrites = ckWrites.then(async () => {
        const tools = await ckLoad(id);
        tools[tool] = state;
        await browser.storage.local.set({ [CK.PREFIX + id]: { tools, updatedAt: new Date().toISOString() } });
    }).catch((e) => console.error("ckSetTool failed:", e));
    return ckWrites;
}

// Node test hook (ignored in the browser)
if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        CK, CkError, ckParseUrlscan, ckParseVirusTotal, ckParseAbuseIpdb, ckDomainAge, ckOverall,
        ckRunTool, ckIsConfigured, ckBase64Url, ckNormalizeUrl, ckIsIp, ckUrlscanSubmit, ckUrlscanWait, ckUrlscanFetchOnce,
    };
}
