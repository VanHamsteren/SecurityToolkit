/* global browser, Busy, CK, ckConfig, ckIsConfigured, ckHasPermission, ckRequestPermissions,
   ckRunTool, ckLoad, ckSetTool, ckOverall, ckDomainAge, ckSleep, ckUrlscanSubmit, ckUrlscanFetchOnce, CkError */
/**
 * Security Toolkit - analysis page
 *
 * One page per link. It walks the user through four steps:
 *   1 Analyse   (automatic, offline: dissect the link, DNS, network, domain age)
 *   2 Check     (reputation: urlscan.io, VirusTotal, AbuseIPDB, domain age, more lookups)
 *   3 Look deeper (optional: fetch the page live from the user's own connection)
 *   4 Decide    (block the domains in NextDNS)
 * ...and combines everything into one overall assessment.
 *
 * Also renders the scan queue (?queue=1) and the history (no parameters).
 *
 * All strings derived from the scanned page or from third parties go through
 * textContent. URLs of the scanned site are never made clickable.
 */

const LIVE_PERMISSIONS = {
    permissions: ["webRequest", "webRequestBlocking"],
    origins: ["<all_urls>"],
};
const REPORT_PREFIX = "qs_";
const STALE_MS = 3 * 60 * 1000;
const LEVEL_TEXT = { clean: "Clean", low: "Low risk", medium: "Suspicious", high: "Malicious", unknown: "No verdict" };

const params = new URLSearchParams(location.search);
const reportId = params.get("id");
const mode = reportId ? "report" : params.get("queue") ? "queue" : "history";
const app = document.getElementById("app");

let current = null;
let profiles = null;
let cfg = {};
let toolState = {};
const perm = {};
const activeRuns = new Set();
let autoRunDone = false;
let focusDone = false;
const regions = {};

// ---------------------------------------------------------------------------
// DOM helpers (no innerHTML)
// ---------------------------------------------------------------------------

function el(tag, attrs = {}, ...children) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
        if (v === null || v === undefined || v === false) continue;
        if (k === "class") n.className = v;
        else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
        else n.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) {
        if (c === null || c === undefined || c === false) continue;
        n.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return n;
}

/** Show these nodes as the page content; empty slots (null) are left out */
function mount(...nodes) {
    app.replaceChildren(...nodes.flat().filter(Boolean));
}

const fmtDate = (v) => {
    if (!v) return "";
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? String(v) : d.toISOString().slice(0, 10);
};

function ageText(days) {
    if (days == null) return "";
    if (days < 60) return `${days} days`;
    if (days < 730) return `${Math.round(days / 30)} months`;
    return `${(days / 365).toFixed(1)} years`;
}

/** Defang for sharing: hxxp and [.] so the URL can't be clicked by accident */
function defang(url) {
    return String(url || "").replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}

function hostOf(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return "";
    }
}

/**
 * The NextDNS denylist, read by the background page (all profiles, all pages).
 * counts: domain -> number of profiles that block it. A parent domain covers its subdomains.
 */
let denylist = null;
async function loadDenylist(force = false) {
    if (!force && denylist && Date.now() - denylist.at < 60000) return denylist;
    try {
        const res = await browser.runtime.sendMessage({ action: "getKnownBlockedDomains", force });
        denylist = { ok: !!res?.success, counts: res?.counts || {}, profiles: res?.profiles || 0, error: res?.error || null, at: Date.now() };
    } catch (e) {
        denylist = { ok: false, counts: {}, profiles: 0, error: e.message, at: Date.now() };
    }
    return denylist;
}

/** In how many profiles is this host (or a parent domain of it) blocked? */
function denylistHits(host, dl) {
    const labels = String(host || "").toLowerCase().split(".");
    let hits = 0;
    for (let i = 0; i < labels.length - 1; i++) hits = Math.max(hits, dl?.counts?.[labels.slice(i).join(".")] || 0);
    return hits;
}

function spinner() {
    return el("span", { class: "spinner", "aria-hidden": "true" });
}

function externalLink(href, label) {
    return el("a", { href, target: "_blank", rel: "noopener noreferrer" }, label);
}

/** Card with an optional title */
function panel(title, ...children) {
    return el("section", { class: "card panel" }, title ? el("h3", {}, title) : null, ...children);
}

function sectionHead(step, title, text) {
    return el("div", { class: "section-head" },
        el("div", { class: "eyebrow" }, step),
        el("h2", {}, title),
        text ? el("p", {}, text) : null);
}

function table(headers, rows, cls = "") {
    return el("div", { class: "tablewrap" }, el("table", { class: cls },
        el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
        el("tbody", {}, rows)));
}

/** "CN=R11,O=Let's Encrypt,C=US" -> "Let's Encrypt (R11)" */
function issuerName(dn) {
    const o = (dn || "").match(/(?:^|,)\s*O=("[^"]+"|[^,]+)/)?.[1]?.replace(/"/g, "");
    const cn = (dn || "").match(/(?:^|,)\s*CN=("[^"]+"|[^,]+)/)?.[1]?.replace(/"/g, "");
    return o && cn ? `${o} (${cn})` : o || cn || dn || "";
}

function region(name) {
    if (!regions[name]) regions[name] = el("div", { id: name, class: "region" });
    return regions[name];
}

function setRegion(name, ...nodes) {
    region(name).replaceChildren(...nodes.filter(Boolean));
}

// ---------------------------------------------------------------------------
// Step model
// ---------------------------------------------------------------------------

function configuredTools() {
    return CK.TOOLS.filter((t) => ckIsConfigured(cfg, t));
}

function stepModel(r) {
    const configured = configuredTools();
    const ran = CK.TOOLS.filter((t) => toolState[t]?.status === "done");
    const running = CK.TOOLS.some((t) => toolState[t]?.status === "running");
    const s1 = r.status === "error" ? "error" : /offline-running/.test(r.status) ? "running" : "done";
    const s2 = running ? "running" : ran.length ? "done" : "todo";
    const s3 = r.status === "live-running" ? "running" : r.live ? "done" : "optional";
    let currentStep = 4;
    if (s1 !== "done") currentStep = 1;
    else if (s2 !== "done" && configured.length) currentStep = 2;
    return { configured, ran, s1, s2, s3, currentStep };
}

// ---------------------------------------------------------------------------
// Regions: head, overall, stepper
// ---------------------------------------------------------------------------

function renderHead(r) {
    return el("div", { class: "target-block" },
        el("div", { class: "eyebrow" }, "Link under analysis"),
        el("div", { class: "target" }, r.target),
        el("div", { class: "sub" }, `Analysed ${new Date(r.createdAt).toLocaleString()}`,
            r.input !== r.target ? ` · the original link was wrapped (${r.unwrapSteps?.map((s) => s.via).join(", ") || "normalised"})` : ""));
}

function renderOverall(r) {
    const o = ckOverall(r, toolState);
    const qs = r.verdict || { score: 0, level: "clean", signals: [] };
    const running = /running/.test(r.status);
    const stale = running && Date.now() - Date.parse(r.updatedAt || r.createdAt) > STALE_MS;

    const chips = [el("span", { class: `chip chip-${qs.level}` }, `Quick Scan ${qs.score}/100`)];
    for (const t of CK.TOOLS) {
        const st = toolState[t];
        if (!st) continue;
        if (st.status === "running") chips.push(el("span", { class: "chip chip-running" }, `${CK.NAMES[t]}: checking`));
        else if (st.status === "error") chips.push(el("span", { class: "chip chip-error" }, `${CK.NAMES[t]}: failed`));
        else chips.push(el("span", { class: `chip chip-${st.level}` }, `${CK.NAMES[t]}: ${st.headline}`));
    }

    const width = o.level === "clean" ? Math.max(4, qs.score) : { low: 25, medium: 55, high: 90 }[o.level];
    const caveat = o.checked === 0 && !r.live
        ? "Based on the offline Quick Scan only. Nothing has been sent to scanners yet, so a low result is not proof the link is safe."
        : o.level === "clean"
            ? "Nothing flagged this link. That lowers the risk but is not proof that it is safe."
            : `${o.flagged ? `${o.flagged} external check${o.flagged === 1 ? "" : "s"} flagged it. ` : ""}Quick Scan counts ${qs.signals.filter((s) => s.score > 0).length} risk signals.`;

    return el("section", { class: "card overall" },
        el("div", { class: "eyebrow" }, "Overall assessment"),
        el("h2", { class: `lvl-${o.level}` }, o.label),
        el("div", { class: "meter", role: "img", "aria-label": `Risk level: ${o.label}` },
            el("div", { class: `bar-${o.level}`, style: `width:${width}%` })),
        el("div", { class: "sources" }, chips),
        running && !stale ? el("div", { class: "status-line" }, spinner(),
            r.status === "live-running" ? "Fetching live and following redirects..." : "Looking up DNS, network and domain age...") : null,
        stale ? el("div", { class: "lvl-high" }, "The analysis was interrupted. Run it again from the link.") : null,
        el("p", { class: "caveat" }, caveat));
}

function renderStepper(r) {
    const m = stepModel(r);
    const state = {
        1: { error: "Failed", running: "Working...", done: "Done" }[m.s1],
        2: m.s2 === "running" ? "Checking..." : m.s2 === "done" ? `${m.ran.length} of ${m.configured.length} done`
            : m.configured.length ? "Not started" : "No API keys set up",
        3: { running: "Working...", done: "Done", optional: "Optional" }[m.s3],
        4: "Your decision",
    };
    const status = { 1: m.s1, 2: m.s2, 3: m.s3, 4: "todo" };
    const items = [
        [1, "Analyse the link", "step1"],
        [2, "Check reputation", "step2"],
        [3, "Look deeper", "step3"],
        [4, "Decide and block", "step4"],
    ].map(([n, title, id]) => el("li", {
        class: `${status[n] === "done" ? "is-done" : ""} ${m.currentStep === n ? "is-current" : ""} ${status[n] === "running" ? "is-running" : ""}`,
    }, el("a", { href: `#${id}`, "aria-current": m.currentStep === n ? "step" : null },
        el("span", { class: "num-badge" }, status[n] === "done" ? "✓" : String(n)),
        el("span", {}, el("div", { class: "step-title" }, title), el("div", { class: "step-state" }, state[n])))));

    const names = m.configured.map((t) => CK.NAMES[t]);
    const o = ckOverall(r, toolState);
    const hint = {
        1: ["Now: ", "analysing the link. This takes a few seconds and sends nothing to scanners."],
        2: ["Next: ", `run the reputation checks. They send the link to ${names.join(", ")}.`],
        4: ["Next: ", o.flagged || o.level === "high" || o.level === "medium"
            ? "review the findings and block the domains you want to keep out."
            : "decide whether to block anything. You can also look deeper by fetching the page live."],
    }[m.currentStep];

    return el("div", {}, el("ol", { class: "stepper" }, items),
        el("p", { class: "next-hint" }, el("span", {}, el("strong", {}, hint[0]), hint[1])));
}

// ---------------------------------------------------------------------------
// Step 1: analysis facts
// ---------------------------------------------------------------------------

function renderSignals(r) {
    const sigs = r.verdict?.signals || [];
    if (!sigs.length) return panel("Signals", el("p", { class: "empty" }, "No signals yet."));
    return panel("What stands out",
        sigs.map((s) => el("div", { class: "signal" },
            el("span", { class: `chip chip-${s.severity}` }, s.severity),
            el("div", {}, el("div", { class: "t" }, s.title), el("div", { class: "d" }, s.detail)))));
}

function renderUrl(r) {
    const u = r.url;
    if (!u) return null;
    const kv = [];
    const add = (k, ...v) => kv.push(el("dt", {}, k), el("dd", {}, ...v));
    if (r.unwrapSteps?.length) add("Unwrapped", r.unwrapSteps.map((s) => s.via).join(" → "));
    add("Host", el("span", { class: "mono" }, u.host), el("span", { class: "muted" }, ` (registrable: ${u.apex})`));
    add("Path", el("span", { class: "mono" }, u.path));
    if (u.query.length) add("Query", el("span", { class: "mono" }, u.query.map((q) => `${q.k}=${q.v}`).join("  &  ")));
    if (u.fragment) add("Fragment", el("span", { class: "mono" }, u.fragment));
    u.decoded.forEach((d) => add(`Base64 (${d.where}${d.key ? ` ${d.key}` : ""})`, el("span", { class: "mono" }, d.decoded)));
    if (u.tracking.length) add("Tracking IDs", el("span", { class: "mono" }, u.tracking.map((t) => `${t.key}=${t.value}`).join(", ")));
    if (u.emails.length) add("E-mail in link", el("span", { class: "mono" }, u.emails.join(", ")));
    if (u.embeddedUrls.length) add("Embedded URLs", el("span", { class: "mono" }, u.embeddedUrls.join("\n")));
    return panel("Link dissection", el("dl", { class: "kv" }, kv));
}

function renderDomains(r) {
    const hosts = Object.values(r.hosts || {});
    if (!hosts.length) return null;
    const rows = hosts.map((h) => el("tr", {},
        el("td", { class: "mono" }, h.host, h.cname?.length ? el("div", { class: "muted" }, `CNAME ${h.cname.join(" → ")}`) : null),
        el("td", { class: "mono" }, h.ips?.slice(0, 2).join(", ") || (h.nxdomain ? "NXDOMAIN" : "")),
        el("td", {}, h.asn ? `AS${h.asn.asn} ${h.asn.asName || ""}` : "", h.asn?.country ? el("span", { class: "muted" }, ` · ${h.asn.country}`) : null),
        el("td", { class: "num" }, h.rdap?.registered ? `${fmtDate(h.rdap.registered)} (${ageText(h.rdap.ageDays)})` : (h.rdap?.found === false ? "no RDAP" : "")),
        el("td", {}, h.rdap?.registrar || ""),
        el("td", { class: "mono muted" }, (h.ns || []).slice(0, 2).join(", ")),
    ));
    return panel("Domains and infrastructure",
        table(["Host", "IP", "Network (ASN)", "Registered", "Registrar", "Name servers"], rows));
}

function renderStep1(r) {
    return el("div", { id: "step1", class: "stack" },
        sectionHead("Step 1", "What the link itself tells us",
            "Worked out on your own computer, without contacting the website: how the link is built, who hosts it and how old the domain is."),
        renderSignals(r),
        el("details", { class: "fold" }, el("summary", {}, "Technical details: link dissection and domains"),
            el("div", { class: "stack" }, renderUrl(r), renderDomains(r))));
}

// ---------------------------------------------------------------------------
// Step 2: reputation checks
// ---------------------------------------------------------------------------

const TOOL_INFO = {
    urlscan: {
        text: () => `Loads the page in a sandbox on urlscan.io's servers and returns a screenshot, the server details and any known verdict. The link is sent to urlscan.io (visibility: ${cfg.urlscanVisibility || "unlisted"}).`,
        privacy: true,
    },
    virustotal: {
        text: () => "Asks about 70 antivirus and blocklist engines what they think of this URL. The link is sent to VirusTotal.",
        privacy: true,
    },
    abuseipdb: {
        text: () => "Looks up the server's IP address in a community database of abuse reports. Only the IP address is sent, not the link.",
        privacy: false,
    },
};

const MORE_LOOKUPS = (domain) => [
    ["Talos Intelligence", `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(domain)}`],
    ["IBM X-Force Exchange", `https://exchange.xforce.ibmcloud.com/url/${encodeURIComponent(domain)}`],
    ["ScamAdviser", `https://www.scamadviser.com/check-website/${encodeURIComponent(domain)}`],
    ["urlscan.io history for this domain", `https://urlscan.io/search/#page.domain%3A%22${encodeURIComponent(domain)}%22`],
    ["VirusTotal domain page", `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`],
    ["Google Safe Browsing", `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(domain)}`],
];

function resultBody(st) {
    const nodes = [];
    nodes.push(el("div", { class: "headline" }, st.headline));
    if (st.details?.length) {
        nodes.push(el("dl", { class: "kv" }, st.details.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, String(v))])));
    }
    if (st.note) nodes.push(el("div", { class: "hint" }, st.note));
    return nodes;
}

/** Nested list of the domain tree urlscan.io recorded */
function chainTree(chain) {
    const kids = new Map();
    for (const n of chain) {
        if (!kids.has(n.parent)) kids.set(n.parent, []);
        kids.get(n.parent).push(n);
    }
    const branch = (n) => {
        const children = kids.get(n.domain) || [];
        return el("li", {},
            el("span", { class: "node-domain" }, n.domain),
            n.via === "redirect" ? el("span", { class: "tag" }, "redirect") : null,
            n.count > 1 ? el("span", { class: "muted" }, ` ${n.count} requests`) : null,
            children.length ? el("ul", {}, children.map(branch)) : null);
    };
    const roots = chain.filter((n) => !n.parent);
    return el("details", { class: "fold chain" },
        el("summary", {}, `Domain chain (${chain.length})`),
        el("ul", { class: "chain-tree" }, roots.map(branch)));
}

function toolCard(r, tool, isCurrentStep) {
    const st = toolState[tool];
    const configured = ckIsConfigured(cfg, tool);
    const info = TOOL_INFO[tool];
    const personalised = r.verdict?.signals?.some((s) => s.id === "personalised");

    let chip;
    let body;
    let actions;
    if (!configured) {
        chip = el("span", { class: "chip chip-unknown" }, "Not set up");
        body = [el("p", { class: "desc" }, info.text()), el("p", { class: "hint" }, `Add your ${CK.NAMES[tool]} API key in the settings to use this check.`)];
        actions = [el("button", { type: "button", class: "btn small", onclick: () => browser.runtime.openOptionsPage() }, "Add API key")];
    } else if (st?.status === "running") {
        chip = el("span", { class: "chip chip-running" }, "Running");
        body = [el("div", { class: "working" }, spinner(), st.note || "Starting..."),
            st.link ? el("div", {}, externalLink(st.link.href, st.link.label)) : null];
        actions = [el("button", { type: "button", class: "btn small is-busy", disabled: true, "aria-busy": "true" }, spinner(), "Running...")];
    } else if (st?.status === "done") {
        chip = el("span", { class: `chip chip-${st.level}` }, LEVEL_TEXT[st.level]);
        body = [
            ...resultBody(st),
            st.chain?.length ? chainTree(st.chain) : null,
            st.screenshot ? el("img", {
                class: "shot", src: st.screenshot, alt: "Screenshot of the page as urlscan.io saw it", loading: "lazy",
                referrerpolicy: "no-referrer", onerror: (e) => e.target.remove(),
            }) : null,
        ];
        actions = [
            st.link ? el("a", { class: "btn small", href: st.link.href, target: "_blank", rel: "noopener noreferrer" }, st.link.label) : null,
            el("button", { type: "button", class: "btn small quiet", onclick: (e) => runOne(tool, e.currentTarget) }, "Run again"),
        ];
    } else if (st?.status === "error") {
        chip = el("span", { class: "chip chip-error" }, "Failed");
        body = [el("div", { class: "err" }, st.error), st.hint ? el("div", { class: "hint" }, st.hint) : null];
        actions = [el("button", { type: "button", class: "btn small", onclick: (e) => runOne(tool, e.currentTarget) }, "Try again")];
    } else {
        chip = el("span", { class: "chip chip-pending" }, "Not run");
        body = [el("p", { class: "desc" }, info.text()),
            info.privacy && personalised ? el("p", { class: "hint" }, "This link looks personalised. A scanner that opens it may register as a click for the recipient.") : null];
        actions = [el("button", { type: "button", class: "btn small", onclick: (e) => runOne(tool, e.currentTarget) },
            perm[tool] ? "Run this check" : "Allow and run")];
    }
    return el("article", { class: "card tool-card", id: `tool-${tool}` },
        el("header", {}, el("h3", {}, CK.NAMES[tool]), chip),
        el("div", { class: "body" }, body),
        el("footer", {}, actions));
}

function ageCard(r) {
    const age = ckDomainAge(r);
    const chip = age ? el("span", { class: `chip chip-${age.level}` }, LEVEL_TEXT[age.level]) : el("span", { class: "chip chip-pending" },
        /running/.test(r.status) ? "Looking up" : "No data");
    return el("article", { class: "card tool-card", id: "tool-rdap" },
        el("header", {}, el("h3", {}, "Domain age"), chip),
        el("div", { class: "body" }, age ? resultBody(age)
            : [el("p", { class: "desc" }, /running/.test(r.status) ? "Reading the registration record (RDAP)..." : "No registration data was found for this domain.")]),
        el("footer", {}, el("span", { class: "hint" }, "From the Quick Scan. Nothing extra is sent.")));
}

function lookupsCard(r) {
    const domain = r.url?.apex || hostOf(r.target);
    return el("article", { class: "card tool-card", id: "tool-lookups" },
        el("header", {}, el("h3", {}, "More lookups"), el("span", { class: "chip chip-info" }, "Links")),
        el("div", { class: "body" },
            el("p", { class: "desc" }, "Open the domain on other analysis sites. Only the domain name is placed in the address."),
            el("ul", { class: "link-list" }, MORE_LOOKUPS(domain).map(([label, href]) => el("li", {}, externalLink(href, label))))));
}

function renderStep2(r) {
    const m = stepModel(r);
    const anyRunning = m.s2 === "running";
    const idle = m.configured.filter((t) => !["running", "done"].includes(toolState[t]?.status));
    let control;
    if (!m.configured.length) {
        control = el("div", { class: "callout info" }, el("strong", {}, "No API keys set up yet. "),
            "Domain age and the Quick Scan work without keys. To check the reputation, add a key for urlscan.io, VirusTotal or AbuseIPDB. ",
            el("div", { class: "row", style: "margin-top:12px" },
                el("button", { type: "button", class: "btn primary", onclick: () => browser.runtime.openOptionsPage() }, "Open settings")));
    } else if (anyRunning) {
        control = el("div", { class: "row" },
            el("button", { type: "button", class: "btn primary is-busy", disabled: true, "aria-busy": "true" }, spinner(), "Checking..."),
            el("span", { class: "muted" }, "Results appear in the cards below as they arrive. Please wait, clicking again will not make it faster."));
    } else if (idle.length) {
        const label = m.ran.length ? `Run the ${idle.length} remaining check${idle.length === 1 ? "" : "s"}` : `Run all checks (${idle.length})`;
        control = el("div", { class: "row" },
            el("button", { type: "button", class: `btn ${m.currentStep === 2 ? "primary" : ""}`, id: "btnRunAll", onclick: runAll }, label),
            el("span", { class: "muted" }, `Sends the link to ${idle.filter((t) => TOOL_INFO[t].privacy).map((t) => CK.NAMES[t]).join(" and ") || "no one"}.`));
    } else {
        control = el("div", { class: "status-line" }, "All checks finished.");
    }
    return el("div", { id: "step2", class: "stack" },
        sectionHead("Step 2", "Ask other services what they know",
            "Each service answers on its own. You can run them together or one by one."),
        control,
        el("div", { class: "tool-grid" },
            CK.TOOLS.map((t) => toolCard(r, t, m.currentStep === 2)), ageCard(r), lookupsCard(r)));
}

// ---------------------------------------------------------------------------
// Step 3: look deeper (live fetch)
// ---------------------------------------------------------------------------

function renderLiveControl(r) {
    if (r.status === "live-running" && Date.now() - Date.parse(r.updatedAt) < STALE_MS) {
        return panel("Live fetch", el("div", { class: "status-line" }, spinner(), "Fetching live and following redirects..."));
    }
    if (!r.url) return null;
    if (r.live && r.status === "done") {
        return panel("Live fetch",
            el("div", { class: "row" },
                el("button", { type: "button", class: "btn", onclick: (e) => runLive(r, e.currentTarget) }, "Fetch again"),
                el("span", { class: "muted" }, `Capture mode: ${r.live.captureMode}. Finished ${r.live.finishedAt ? new Date(r.live.finishedAt).toLocaleTimeString() : ""}`)));
    }
    const personalised = r.verdict?.signals?.some((s) => s.id === "personalised");
    const follow = el("input", { type: "checkbox", id: "followClient", checked: true });
    return panel("Live fetch (optional)",
        el("div", { class: "callout" },
            el("strong", {}, "This contacts the target server from your own internet connection. "),
            "No cookies, Referer or Origin are sent, and nothing is rendered or executed: the response is only read as text. ",
            "Your IP address is visible to the server, which is also why this often sees what a real victim sees.",
            personalised ? el("p", { style: "margin-top:8px" }, el("strong", {}, "Personalised link: "),
                "fetching it will likely register as a click for this recipient and confirm the mailbox is active.") : null),
        el("div", { class: "row", style: "margin-top:14px" },
            el("button", { type: "button", class: "btn", id: "btnLive", onclick: (e) => runLive(r, e.currentTarget) }, "Fetch the page live"),
            el("label", { style: "display:flex;gap:8px;align-items:center;font-size:14px" }, follow,
                "Follow meta-refresh and JavaScript redirects")),
        el("div", { class: "toast", id: "liveMsg", role: "status" }));
}

function renderChain(r) {
    const hops = r.live?.hops || [];
    if (!hops.length) return null;
    const rows = hops.map((h, i) => el("tr", {},
        el("td", { class: "num" }, String(i)),
        el("td", {}, el("span", { class: `chip chip-${h.kind || "http"}` }, h.kind || "http")),
        el("td", { class: "mono" }, h.url, h.error ? el("div", { class: "lvl-high" }, h.error) : null),
        el("td", { class: "num" }, h.status ?? "-"),
        el("td", { class: "mono" }, h.ip || ""),
        el("td", { class: "muted" }, h.tls ? `${issuerName(h.tls.issuer)}${h.tls.ageDays != null ? `, cert ${h.tls.ageDays}d old` : ""}` : ""),
    ));
    const f = r.live.final;
    return panel(`Redirect chain (${Math.max(0, hops.length - 1)} hops)`,
        table(["#", "Type", "URL", "Status", "IP", "TLS"], rows),
        f ? el("dl", { class: "kv", style: "margin-top:14px" },
            el("dt", {}, "Final response"), el("dd", {}, `${f.status} · ${f.contentType || "no content-type"} · ${f.size.toLocaleString()} bytes${f.truncated ? " (truncated)" : ""}`),
            el("dt", {}, "SHA-256"), el("dd", { class: "mono" }, f.sha256, " ",
                externalLink(`https://www.virustotal.com/gui/file/${f.sha256}`, "VirusTotal")),
            f.filename ? [el("dt", {}, "File name"), el("dd", { class: "mono" }, f.filename)] : null,
            hops[hops.length - 1]?.headers?.server ? [el("dt", {}, "Server"), el("dd", {}, hops[hops.length - 1].headers.server)] : null,
        ) : null,
        r.live.error ? el("p", { class: "lvl-high", style: "margin-top:10px" }, r.live.error) : null);
}

function renderPages(r) {
    const pages = r.live?.pages || [];
    if (!pages.length) return null;
    return panel("Page analysis (static, nothing executed)", pages.map((p) => {
        const a = p.analysis;
        return el("div", { class: "page-block" },
            el("div", { class: "mono", style: "margin-bottom:8px" }, p.url),
            el("dl", { class: "kv" },
                el("dt", {}, "Title"), el("dd", {}, a.title || "(none)"),
                el("dt", {}, "Visible text"), el("dd", {}, `${a.textLength} characters`),
                el("dt", {}, "Password fields"), el("dd", {}, String(a.passwordFields)),
                el("dt", {}, "Inline script"), el("dd", {}, `${a.inlineScriptBytes.toLocaleString()} bytes`),
                a.pageBrands.length ? [el("dt", {}, "Brands mentioned"), el("dd", {}, a.pageBrands.join(", "))] : null,
            ),
            a.forms.length ? el("div", { style: "margin-top:12px" },
                table(["Form action", "Method", "Fields"], a.forms.map((f) => el("tr", {},
                    el("td", { class: "mono" }, f.action || ""),
                    el("td", {}, f.method.toUpperCase()),
                    el("td", { class: "mono" }, f.inputs.map((i) => `${i.type}${i.name ? `:${i.name}` : ""}${i.value ? `=${i.value}` : ""}`).join(", ")))))) : null,
            a.referencedDomains.length ? el("details", {},
                el("summary", {}, `Referenced domains (${a.referencedDomains.length})`),
                table(["Domain", "Used for", "Count"], a.referencedDomains.map((d) => el("tr", {},
                    el("td", { class: "mono" }, d.host), el("td", {}, d.kinds.join(", ")), el("td", { class: "num" }, String(d.count)))))) : null,
            a.textSample ? el("details", {}, el("summary", {}, "Text sample"), el("p", { class: "muted", style: "margin-top:6px" }, a.textSample)) : null,
        );
    }));
}

function renderStep3(r) {
    return el("div", { id: "step3", class: "stack" },
        sectionHead("Step 3 · optional", "Look at the page itself",
            "Only needed when the checks above leave questions. This is the one step that contacts the website."),
        renderLiveControl(r), renderChain(r), renderPages(r));
}

// ---------------------------------------------------------------------------
// Step 4: decide and block
// ---------------------------------------------------------------------------

async function loadProfiles() {
    if (profiles) return profiles;
    try {
        const res = await browser.runtime.sendMessage({ action: "qsNextDnsProfiles" });
        profiles = res?.profiles?.length ? res.profiles : null; // an empty answer is not cached, so the next panel retries
    } catch {
        profiles = null;
    }
    return profiles || [];
}

/** Shared by the single-link page and the queue page */
function blockPanel(cands, { primary, intro }) {
    const boxes = cands.map((c) => {
        const cb = el("input", { type: "checkbox", value: c.domain, checked: c.checked, id: `cb-${c.domain}` });
        return el("div", { class: "cand" }, cb,
            el("label", { for: `cb-${c.domain}` }, c.domain, el("span", { class: "why" }, c.reasons.join(", "))));
    });
    const select = el("select", { id: "profileSel", "aria-label": "NextDNS profile" });
    const msg = el("div", { class: "toast", role: "status" });
    const blockBtn = el("button", { type: "button", class: `btn ${primary ? "primary" : "danger"}`, id: "btnBlock" }, "Block in NextDNS");
    blockBtn.addEventListener("click", () => Busy.run(blockBtn, "Blocking...", () => blockSelected(select, msg)));
    loadProfiles().then((list) => {
        select.replaceChildren();
        if (!list.length) {
            select.append(el("option", { value: "" }, "NextDNS is not set up"));
            select.disabled = true;
            blockBtn.disabled = true;
            return;
        }
        if (list.length > 1) select.append(el("option", { value: "all" }, "All profiles"));
        list.forEach((p) => select.append(el("option", { value: p.id }, p.name)));
    });
    const note = el("p", { class: "muted", style: "margin-top:10px;font-size:13px" });
    const actions = el("div", { class: "row", style: "margin-top:14px" }, select, blockBtn);
    const node = panel("Block domains",
        el("p", { class: "muted", style: "margin-bottom:12px" }, intro),
        cands.length ? boxes : el("p", { class: "empty" }, "No domains to suggest."),
        actions, msg, note);
    // Domains that are already on the NextDNS denylist are not suggested again
    loadDenylist().then((dl) => {
        if (!dl.ok) {
            if (cands.length && dl.error && dl.error !== "NextDNS is not set up") {
                note.textContent = `Could not read your NextDNS denylist (${dl.error}), so domains you already block are not marked.`;
            }
            return;
        }
        let already = 0;
        for (const box of node.querySelectorAll(".cand")) {
            const input = box.querySelector("input");
            const hits = denylistHits(input.value, dl);
            if (!hits) continue;
            const why = box.querySelector(".why");
            if (hits >= dl.profiles) {
                input.checked = false;
                input.disabled = true;
                box.classList.add("blocked");
                why.append(" · already on your NextDNS denylist");
                actions.before(box); // blocked domains go to the bottom of the list
                already++;
            } else {
                why.append(` · on the denylist of ${hits} of ${dl.profiles} profiles`);
            }
        }
        if (already) note.textContent = `${already} domain${already === 1 ? " is" : "s are"} already on your NextDNS denylist and cannot be ticked.`;
    });
    return node;
}

async function blockSelected(select, msg) {
    const domains = [...document.querySelectorAll(".cand input:checked")].map((c) => c.value);
    if (!domains.length || !select.value) {
        msg.textContent = "Tick at least one domain first.";
        return;
    }
    msg.textContent = "";
    try {
        const res = await browser.runtime.sendMessage({ action: "qsNextDnsBlock", domains, profileId: select.value });
        const ok = res.results.filter((x) => x.ok).length;
        const failed = res.results.filter((x) => !x.ok);
        msg.textContent = `Added ${ok} entr${ok === 1 ? "y" : "ies"} to the NextDNS denylist${failed.length ? `, ${failed.length} failed (${failed[0].error})` : ""}.`;
        msg.className = `toast ${failed.length ? "lvl-high" : "lvl-clean"}`;
        denylist = null; // read the list again next time
    } catch (e) {
        msg.textContent = `Could not block: ${e.message}`;
        msg.className = "toast lvl-high";
    }
}

// Domains from the urlscan.io chain, filtered in the background script (it holds the popular-site and platform lists)
const chainCands = { key: "", list: [] };

async function loadChainCands() {
    const st = toolState.urlscan;
    const chain = st?.status === "done" ? st.chain : null;
    const key = chain?.length ? `${st.finishedAt}:${chain.length}` : "";
    if (key === chainCands.key) return;
    chainCands.key = key;
    chainCands.list = [];
    if (!key) return;
    try {
        const res = await browser.runtime.sendMessage({
            action: "qsBlockCandidatesForChain", chain, flagged: st.level === "high" || st.level === "medium",
        });
        if (chainCands.key === key) chainCands.list = res?.candidates || [];
    } catch {
        /* the block panel simply shows no chain suggestions */
    }
    if (chainCands.key === key && chainCands.list.length) setRegion("step4", renderStep4(current));
}

function renderStep4(r) {
    const m = stepModel(r);
    const o = ckOverall(r, toolState);
    // keep what the user already ticked when the panel is redrawn
    const touched = new Map([...region("step4").querySelectorAll(".cand input")].map((c) => [c.value, c.checked]));
    const flagged = o.level === "medium" || o.level === "high";
    const fromChain = chainCands.list.filter((c) => !(r.blockCandidates || []).some((b) => b.domain === c.domain));
    const cands = [...(r.blockCandidates || []), ...fromChain].map((c) => ({
        ...c,
        checked: touched.has(c.domain) ? touched.get(c.domain) : (c.checked || (flagged && c.reasons.includes("link in the message"))),
        reasons: flagged && !c.reasons.includes("flagged by the checks") && c.reasons.includes("link in the message") && o.flagged
            ? [...c.reasons, "flagged by the checks"] : c.reasons,
    }));
    return el("div", { id: "step4", class: "stack" },
        sectionHead("Step 4", "Decide what to block",
            "Blocking in NextDNS stops every device on your profile from reaching these domains."),
        blockPanel(cands, { primary: m.currentStep === 4 && cands.length > 0, intro: "Domains found in this analysis. Suggestions that look risky are ticked. Popular and shared platforms are never suggested." }));
}

// ---------------------------------------------------------------------------
// Running tools
// ---------------------------------------------------------------------------

function redrawChecks(r = current) {
    if (!r) return;
    setRegion("overall", renderOverall(r));
    setRegion("stepper", renderStepper(r));
    setRegion("step2", renderStep2(r));
}

function setTool(tool, state, persist = true) {
    toolState[tool] = state;
    if (persist && reportId) ckSetTool(reportId, tool, state);
    redrawChecks();
}

async function runTool(tool) {
    if (activeRuns.has(tool) || !current) return;
    activeRuns.add(tool);
    setTool(tool, { tool, status: "running", note: "Starting...", startedAt: Date.now() });
    Busy.begin(`Checking ${CK.NAMES[tool]}`);
    const ctx = {
        url: current.target,
        host: current.url?.host || hostOf(current.target),
        ip: current.hosts?.[current.url?.host]?.ips?.[0] || null,
    };
    const result = await ckRunTool(tool, ctx, cfg, (u) => {
        if (activeRuns.has(tool)) setTool(tool, { ...toolState[tool], status: "running", ...u }, false);
    });
    activeRuns.delete(tool);
    Busy.end(`${CK.NAMES[tool]} finished`);
    setTool(tool, result);
    renderStep4Region();
}

/** Single card button. The permission request must be the first await (user gesture). */
async function runOne(tool, button) {
    if (activeRuns.has(tool)) return;
    let granted = true;
    if (!perm[tool]) granted = await ckRequestPermissions([tool]);
    if (!granted) {
        setTool(tool, { tool, status: "error", error: `${CK.NAMES[tool]} needs permission to be contacted.`, hint: "Choose Allow in the prompt, or grant it under about:addons > Security Toolkit > Permissions." }, false);
        return;
    }
    perm[tool] = true;
    runTool(tool);
    if (button) button.blur();
}

async function runAll() {
    const tools = configuredTools().filter((t) => !["running", "done"].includes(toolState[t]?.status));
    if (!tools.length) return;
    const need = tools.filter((t) => !perm[t]);
    // one permission prompt for all tools; first await keeps the user gesture
    const granted = need.length ? await ckRequestPermissions(need) : true;
    if (!granted) {
        need.forEach((t) => setTool(t, { tool: t, status: "error", error: `${CK.NAMES[t]} needs permission to be contacted.`, hint: "Choose Allow in the prompt, or grant it under about:addons > Security Toolkit > Permissions." }, false));
        return;
    }
    need.forEach((t) => {
        perm[t] = true;
    });
    // parallel, but start VirusTotal a little later so its 4-requests-a-minute limit is not hit at the same time as others
    tools.forEach((t) => runTool(t));
}

function renderStep4Region() {
    if (!current) return;
    setRegion("step4", renderStep4(current));
    loadChainCands();
}

async function maybeAutoRun(r) {
    if (autoRunDone) return;
    autoRunDone = true;
    const wanted = (params.get("run") || "").split(",").map((s) => s.trim()).filter(Boolean);
    const list = wanted.includes("all") ? CK.TOOLS : wanted.filter((t) => CK.TOOLS.includes(t));
    for (const t of list) {
        if (!ckIsConfigured(cfg, t) || ["running", "done"].includes(toolState[t]?.status)) continue;
        if (perm[t]) runTool(t); // without permission the card shows "Allow and run" (needs a click)
    }
    if (!focusDone) {
        focusDone = true;
        const focus = params.get("focus") || (list.length === 1 ? list[0] : "");
        const card = focus && document.getElementById(`tool-${focus}`);
        if (card) {
            card.classList.add("is-focus");
            card.scrollIntoView({ block: "center" });
        }
    }
    void r;
}

// ---------------------------------------------------------------------------
// Live fetch (Quick Scan engine)
// ---------------------------------------------------------------------------

async function runLive(r, button) {
    const go = async () => {
        // permissions.request must be the first await to keep the user gesture
        let granted = false;
        try {
            granted = await browser.permissions.request(LIVE_PERMISSIONS);
        } catch (e) {
            console.error("Permission request failed:", e);
        }
        const msg = document.getElementById("liveMsg");
        if (!granted) {
            if (msg) msg.textContent = "Live fetch needs access to all websites and to network requests. Nothing was fetched.";
            return;
        }
        const follow = document.getElementById("followClient");
        await browser.runtime.sendMessage({ action: "qsRunLive", id: r.id, options: { followClient: follow ? follow.checked : true } });
    };
    if (button) return Busy.run(button, "Starting...", go);
    return go();
}

async function maybeAutoLive(r) {
    if (r.live || r.status !== "offline-done" || maybeAutoLive.done) return;
    maybeAutoLive.done = true;
    const { qsLiveMode = "ask" } = await browser.storage.sync.get("qsLiveMode");
    if (qsLiveMode !== "auto") return;
    if (!(await browser.permissions.contains(LIVE_PERMISSIONS))) return;
    await browser.runtime.sendMessage({ action: "qsRunLive", id: r.id });
}

// ---------------------------------------------------------------------------
// Page assembly
// ---------------------------------------------------------------------------

function render(r) {
    current = r;
    if (!r) {
        app.replaceChildren(panel("Analysis not found",
            el("p", { class: "empty" }, "This analysis may have been rotated out of the history."),
            el("p", { style: "margin-top:12px" }, el("a", { class: "btn", href: "report.html" }, "Recent analyses"))));
        return;
    }
    document.title = `Security Toolkit - ${hostOf(r.target) || "analysis"}`;
    if (!app.contains(region("overall"))) {
        app.replaceChildren(region("head"), region("overall"), region("stepper"), region("step1"), region("step2"), region("step3"), region("step4"));
    }
    setRegion("head", renderHead(r));
    setRegion("overall", renderOverall(r));
    setRegion("stepper", renderStepper(r));
    setRegion("step1", renderStep1(r));
    setRegion("step2", renderStep2(r));
    setRegion("step3", renderStep3(r));
    renderStep4Region();
    maybeAutoLive(r);
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

async function renderHistory() {
    const { quickScanIndex: index = [] } = await browser.storage.local.get("quickScanIndex");
    const { urlscanQueue: queue = [] } = await browser.storage.local.get("urlscanQueue");
    const pending = queue.filter((i) => i.status === "pending").length;
    mount(
        el("div", { class: "section-head" }, el("div", { class: "eyebrow" }, "Security Toolkit"), el("h2", {}, "Recent analyses"),
            el("p", {}, "Right-click any link, choose Security Analysis and then Analyse link. The result opens here, with one clear flow: analyse, check, look deeper, decide.")),
        queue.length ? el("div", { class: "card", style: "margin-bottom:16px" },
            el("div", { class: "row" }, el("strong", {}, `Scan queue: ${queue.length} link${queue.length === 1 ? "" : "s"}${pending ? `, ${pending} waiting` : ""}`),
                el("span", { class: "spacer", style: "flex:1" }),
                el("a", { class: "btn", href: "report.html?queue=1" }, "Open the scan queue"))) : null,
        panel(null, index.length
            ? el("div", { class: "history" }, index.map((i) => el("a", { class: "item", href: `report.html?id=${encodeURIComponent(i.id)}` },
                el("span", { class: "muted num" }, new Date(i.createdAt).toLocaleString()), el("span", { class: "mono" }, defang(i.target)))))
            : el("p", { class: "empty" }, "No analyses yet.")));
}

// ---------------------------------------------------------------------------
// Scan queue page
// ---------------------------------------------------------------------------

// Two queues share this page: the toolkit's own (?queue=1, the tools you tick)
// and a separate one that only sends links to urlscan.io (?queue=urlscan)
const URLSCAN_ONLY = params.get("queue") === "urlscan";
const QUEUE_KEY = URLSCAN_ONLY ? "urlscanOnlyQueue" : "urlscanQueue";
const HEARTBEAT_KEY = URLSCAN_ONLY ? "urlscanOnlyHeartbeat" : "urlscanHeartbeat";
const QUEUE_ADD_HINT = URLSCAN_ONLY
    ? "Right-click a link or selected text and choose Security Analysis > URLScan.io > Add to urlscan.io queue."
    : "Right-click a link or selected text and choose Security Analysis > Add to queue.";

const queueState = { items: [], running: false, progress: null, cands: null, message: "", note: "", runId: 0, earlierOpen: false };

async function loadQueue() {
    queueState.items = (await browser.storage.local.get(QUEUE_KEY))[QUEUE_KEY] || [];
    // Nothing is running here, so a link still marked "scanning" was interrupted: put it back in line
    if (!queueState.running) {
        let changed = false;
        for (const it of queueState.items) {
            if (it.status === "scanning") {
                it.status = "pending";
                it.error = null;
                changed = true;
            }
        }
        if (changed) await saveQueue();
    }
}

/**
 * Save the queue. Links added from the right-click menu while this page is open exist only in storage,
 * so they are merged in first; otherwise this page would overwrite them with its older copy.
 * Pass { replace: true } after an explicit remove or clear.
 */
async function saveQueue({ replace = false } = {}) {
    if (!replace) {
        const stored = (await browser.storage.local.get(QUEUE_KEY))[QUEUE_KEY] || [];
        const known = new Set(queueState.items.map((i) => i.url));
        queueState.items.push(...stored.filter((i) => !known.has(i.url)));
    }
    await browser.storage.local.set({ [QUEUE_KEY]: queueState.items });
}

// Links whose domain is already blocked in every NextDNS profile are skipped, unless this is ticked
const RESCAN_KEY = "queueRescanBlocked";
queueState.rescanBlocked = false;

/** Put links that were skipped as "already blocked" back in line */
function requeueSkipped() {
    let n = 0;
    for (const it of queueState.items) {
        if (!it.blocked) continue;
        it.blocked = false;
        it.status = "pending";
        n++;
    }
    return n;
}

function rescanOption() {
    const input = el("input", {
        type: "checkbox", id: "qRescanBlocked", checked: queueState.rescanBlocked, disabled: queueState.running,
        onchange: async (e) => {
            queueState.rescanBlocked = e.target.checked;
            await browser.storage.local.set({ [RESCAN_KEY]: queueState.rescanBlocked });
            if (queueState.rescanBlocked && requeueSkipped()) await saveQueue({ replace: true });
            drawQueue();
        },
    });
    return el("label", { for: "qRescanBlocked", style: "display:flex;gap:8px;align-items:center;font-size:14px;margin-top:12px" }, input,
        "Also analyse links whose domain is already on my NextDNS denylist");
}

const BATCH_SIZE = 20;
const WORKERS = 3;
queueState.tools = { urlscan: true, abuseipdb: true, virustotal: false }; // VirusTotal is slow (4 a minute), so opt-in

/** Spaces out the start of calls to a rate-limited service */
const gates = {};
function gate(name, ms) {
    const previous = gates[name] || Promise.resolve();
    gates[name] = previous.then(() => ckSleep(ms));
    return previous;
}

function queueStatusChip(it) {
    const labels = { pending: "Waiting", scanning: "Scanning", completed: "Done", failed: "Failed" };
    return el("span", { class: `chip chip-${it.status}` }, labels[it.status] || it.status);
}

function resultChips(it) {
    const chips = [];
    if (it.denylisted) chips.push(el("span", { class: "chip chip-info" }, "Already blocked in NextDNS"));
    if (it.quick) chips.push(el("span", { class: `chip chip-${it.quick.level}` }, `Quick Scan ${it.quick.score}/100`));
    if (it.age) chips.push(el("span", { class: `chip chip-${it.age.level}` }, `Domain age: ${it.age.headline}`));
    for (const t of CK.TOOLS) {
        const r = it.tools?.[t];
        if (!r) continue;
        chips.push(r.status === "error"
            ? el("span", { class: "chip chip-error", title: r.error || "" }, `${CK.NAMES[t]}: failed`)
            : el("span", { class: `chip chip-${r.level}` }, `${CK.NAMES[t]}: ${r.headline}`));
    }
    return chips.length ? el("div", { class: "sources", style: "margin:6px 0 0" }, chips) : null;
}

function queueRow(it) {
    return el("tr", {},
        el("td", {}, queueStatusChip(it)),
        el("td", { class: "url" }, defang(it.target || it.url)),
        el("td", {},
            it.blocked ? el("span", { class: "chip chip-info" }, "Already blocked in NextDNS")
                : it.result ? el("span", { class: `chip chip-${it.result.level}` }, it.result.level === "unknown" ? it.result.headline : (LEVEL_TEXT[it.result.level] || it.result.headline))
                : it.error ? el("span", { class: "lvl-high", style: "font-size:13px" }, it.error)
                    : it.status === "scanning" ? el("span", { class: "status-line" }, spinner(), "Analysing...") : el("span", { class: "muted" }, "-"),
            resultChips(it)),
        el("td", {}, el("div", { class: "row" },
            it.reportId
                ? el("a", { class: "btn small", href: `report.html?id=${encodeURIComponent(it.reportId)}`, target: "_blank", rel: "noopener noreferrer" }, "Full analysis")
                : el("button", { type: "button", class: "btn small", onclick: () => browser.runtime.sendMessage({ action: "qsRescanOffline", url: it.url, run: "all" }) }, "Full analysis"),
            el("button", { type: "button", class: "btn small quiet", disabled: queueState.running && it.status === "scanning", onclick: () => removeFromQueue(it.url) }, "Remove"))));
}

async function removeFromQueue(url) {
    queueState.items = queueState.items.filter((i) => i.url !== url);
    await saveQueue({ replace: true });
    await browser.runtime.sendMessage({ action: "fetchProfiles" }).catch(() => {});
    drawQueue();
}

function selectedQueueTools() {
    if (URLSCAN_ONLY) return ckIsConfigured(cfg, "urlscan") ? ["urlscan"] : [];
    return CK.TOOLS.filter((t) => queueState.tools[t] && ckIsConfigured(cfg, t));
}

function toolPicker() {
    if (URLSCAN_ONLY) {
        return el("div", { class: "muted", style: "font-size:13px;margin-top:12px" },
            "Every link gets the Quick Scan and the domain age, and is then sent to urlscan.io only.");
    }
    const boxes = CK.TOOLS.filter((t) => ckIsConfigured(cfg, t)).map((t) => {
        const input = el("input", {
            type: "checkbox", id: `qt-${t}`, checked: !!queueState.tools[t], disabled: queueState.running,
            onchange: (e) => {
                queueState.tools[t] = e.target.checked;
            },
        });
        return el("label", { for: `qt-${t}`, style: "display:flex;gap:8px;align-items:center;font-size:14px" }, input,
            t === "virustotal" ? "VirusTotal (slow: 4 links a minute)" : CK.NAMES[t]);
    });
    return el("div", { class: "stack", style: "margin-top:12px" },
        el("div", { class: "muted", style: "font-size:13px" }, "Every link gets the Quick Scan and the domain age. Also check each link with:"),
        el("div", { class: "row", style: "gap:20px" }, boxes));
}

function drawQueue() {
    const items = queueState.items;
    // The latest scan (and anything still waiting) on top; older results tucked away
    const lastRun = Math.max(queueState.runId || 0, ...items.map((i) => i.runId || 0));
    const isEarlier = (i) => ["completed", "failed"].includes(i.status) && (!lastRun || (i.runId || 0) !== lastRun);
    const currentItems = items.filter((i) => !isEarlier(i));
    const earlierItems = items.filter(isEarlier);
    const noTools = URLSCAN_ONLY ? !ckIsConfigured(cfg, "urlscan") : !CK.TOOLS.some((t) => ckIsConfigured(cfg, t));
    const pendingItems = items.filter((i) => i.status === "pending");
    const pending = pendingItems.length;
    const batch = Math.min(BATCH_SIZE, pending);
    const done = items.filter((i) => i.status === "completed");
    const flagged = done.filter((i) => i.result && (i.result.level === "high" || i.result.level === "medium")).length;
    const failed = items.filter((i) => i.status === "failed").length;
    const p = queueState.progress;

    let control;
    if (queueState.running) {
        control = el("div", { class: "stack" },
            el("div", { class: "row" },
                el("button", { type: "button", class: "btn primary is-busy", disabled: true, "aria-busy": "true" }, spinner(), "Analysing..."),
                el("span", { class: "muted" }, p ? `${p.finished} of ${p.total} links finished. You can keep browsing, but leave this tab open.` : "Starting...")),
            el("div", { class: "progress", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": String(p?.total || 1), "aria-valuenow": String(p?.finished || 0) },
                el("div", { style: `width:${p && p.total ? Math.round((p.finished / p.total) * 100) : 0}%` })));
    } else if (pending) {
        control = el("div", { class: "stack" },
            el("div", { class: "row" },
                el("button", { type: "button", class: "btn primary", id: "btnScanQueue", onclick: runQueue }, `Analyse the next ${batch} link${batch === 1 ? "" : "s"}`),
                el("span", { class: "muted" }, pending > batch ? `${pending} are waiting. They are done in batches of ${BATCH_SIZE} to respect the free limits of the tools.` : "All waiting links are included.")),
            toolPicker(), rescanOption());
    } else {
        control = el("div", { class: "stack" },
            el("p", { class: "muted" }, `${items.length ? "Nothing waiting." : "The queue is empty."} ${QUEUE_ADD_HINT}`),
            items.some((i) => i.blocked) || queueState.rescanBlocked ? rescanOption() : null);
    }

    const blockNodes = queueState.cands && queueState.cands.length && !queueState.running
        ? [el("div", { class: "section-head", style: "margin-top:24px" }, el("div", { class: "eyebrow" }, "Step 3"), el("h2", {}, "Decide what to block"),
            el("p", {}, "Links the checks flagged are ticked. Review them before you block."))]
            .concat([blockPanel(queueState.cands, { primary: true, intro: "Domains from the batch, including every domain urlscan.io saw while loading each link. Popular and shared platforms are never suggested." })])
        : [];

    mount(
        el("div", { class: "section-head" }, el("div", { class: "eyebrow" }, "Security Toolkit"), el("h2", {}, URLSCAN_ONLY ? "urlscan.io queue" : "Scan queue"),
            el("p", {}, URLSCAN_ONLY
                ? "Links collected for urlscan.io only. One button sends them all to urlscan.io, then you block the bad ones. "
                : "Collect suspicious links during the day. One button analyses them all with every tool, then you block the bad ones: add, analyse, decide. ",
            el("a", { href: URLSCAN_ONLY ? "report.html?queue=1" : "report.html?queue=urlscan" }, URLSCAN_ONLY ? "Open the scan queue for all tools" : "Open the urlscan.io queue"))),
        el("section", { class: "card stack" },
            el("div", { class: "eyebrow" }, "Step 2 · analyse"),
            el("div", { class: "row" },
                el("span", { class: "chip chip-pending" }, `${pending} waiting`),
                el("span", { class: "chip chip-done" }, `${done.length} done`),
                flagged ? el("span", { class: "chip chip-high" }, `${flagged} flagged`) : null,
                failed ? el("span", { class: "chip chip-failed" }, `${failed} failed`) : null),
            control,
            queueState.message ? el("p", { class: "toast lvl-high" }, queueState.message) : null,
            queueState.note ? el("p", { class: "muted" }, queueState.note) : null),
        noTools && items.length ? el("p", { class: "toast lvl-medium", style: "margin-top:16px" },
            URLSCAN_ONLY ? "urlscan.io is not set up on this computer, so links are only checked offline. "
                : "No reputation tool (urlscan.io, VirusTotal, AbuseIPDB) is set up on this computer, so links are only checked offline. ",
            "An offline check cannot prove a link is safe: spam links often show a harmless page to scanners. Add your API keys in Settings.") : null,
        currentItems.length ? el("section", { class: "card", style: "margin-top:16px" },
            el("h3", {}, lastRun && currentItems.some((i) => i.runId === lastRun) ? `This scan (${currentItems.length})` : `Waiting (${currentItems.length})`),
            table(["Status", "Link", "Verdict", ""], currentItems.map(queueRow), "queue-table")) : null,
        earlierItems.length ? el("section", { class: "card", style: "margin-top:16px" },
            el("details", { open: queueState.earlierOpen, ontoggle: (e) => { queueState.earlierOpen = e.target.open; } },
                el("summary", {}, `Earlier scans (${earlierItems.length})`),
                table(["Status", "Link", "Verdict", ""], earlierItems.map(queueRow), "queue-table"),
                el("div", { class: "row", style: "margin-top:12px" },
                    el("button", { type: "button", class: "btn small", disabled: queueState.running, onclick: clearEarlier }, "Remove earlier scans")))) : null,
        items.length ? el("div", { class: "row", style: "margin-top:12px" },
            el("button", { type: "button", class: "btn small danger", disabled: queueState.running, onclick: clearQueueNow }, "Clear the queue")) : null,
        ...blockNodes);
}

async function clearEarlier() {
    const lastRun = Math.max(queueState.runId || 0, ...queueState.items.map((i) => i.runId || 0));
    queueState.items = queueState.items.filter((i) => !(["completed", "failed"].includes(i.status) && (!lastRun || (i.runId || 0) !== lastRun)));
    await saveQueue({ replace: true });
    drawQueue();
}

async function clearQueueNow() {
    if (!confirm("Remove every link from the scan queue?")) return;
    queueState.items = [];
    queueState.cands = null;
    await saveQueue({ replace: true });
    await browser.runtime.sendMessage({ action: "fetchProfiles" }).catch(() => {});
    drawQueue();
}

/** One link: Quick Scan first (gives the IP and domain age), then the chosen tools side by side */
async function processItem(it, tools) {
    it.status = "scanning";
    it.error = null;
    it.tools = {};
    it.runId = queueState.runId;
    await saveQueue();
    drawQueue();

    const res = await browser.runtime.sendMessage({ action: "qsRescanOffline", url: it.url, openTab: false });
    if (!res?.id) throw new Error("This is not a valid link or domain.");
    const key = REPORT_PREFIX + res.id;
    const report = (await browser.storage.local.get(key))[key];
    if (!report) throw new Error("The Quick Scan result went missing.");
    it.reportId = res.id;
    it.target = report.target;

    const host = report.url?.host || hostOf(report.target);
    const ctx = { url: report.target, host, ip: report.hosts?.[host]?.ips?.[0] || null };
    const states = {};
    await Promise.all(tools.map(async (t) => {
        if (t === "virustotal") await gate("vt", 16000);
        if (t === "urlscan") await gate("urlscan", 2500);
        const st = await ckRunTool(t, ctx, cfg, () => {});
        states[t] = st;
        it.tools[t] = { status: st.status, level: st.level, headline: st.headline, error: st.error };
        await ckSetTool(res.id, t, st);
        drawQueue();
    }));

    // Domains urlscan.io saw for this link, kept for the block step
    it.chain = (states.urlscan?.chain || []).map((n) => n.domain);
    const overall = ckOverall(report, states);
    const age = ckDomainAge(report);
    it.quick = { score: report.verdict?.score ?? 0, level: report.verdict?.level || "clean" };
    it.age = age ? { level: age.level, headline: age.headline } : null;
    // Only the offline Quick Scan ran: that says "no signals found", not "safe"
    const verified = Object.values(states).some((s) => s.status === "done");
    it.result = verified ? { level: overall.level, headline: overall.label }
        : overall.level === "clean" ? { level: "unknown", headline: "Not verified (offline checks only)" }
            : { level: overall.level, headline: overall.label };
    it.status = "completed";
}

async function runQueue() {
    if (queueState.running) return;
    const tools = selectedQueueTools();
    // permission request first: it needs the click gesture
    const granted = tools.length ? await ckRequestPermissions(tools) : true;
    if (!granted) {
        queueState.message = "A selected tool needs permission to be contacted. Choose Allow in the prompt and try again.";
        drawQueue();
        return;
    }
    await startQueueRun(tools);
}

async function startQueueRun(tools = selectedQueueTools()) {
    queueState.running = true;
    queueState.message = "";
    queueState.cands = null;
    cfg = await ckConfig();
    await loadQueue();
    queueState.runId = Date.now(); // this scan; everything finished before it is shown under "Earlier scans"
    // Links whose domain is blocked in every NextDNS profile need no analysis: skip them
    queueState.note = "";
    const dl = await loadDenylist(true);
    if (queueState.rescanBlocked) {
        // analyse them anyway, but keep telling the user they are blocked already
        for (const it of queueState.items) {
            if (it.status === "pending") it.denylisted = dl.ok && dl.profiles > 0 && denylistHits(hostOf(it.url), dl) >= dl.profiles;
        }
    } else if (dl.ok && dl.profiles) {
        let skipped = 0;
        for (const it of queueState.items) {
            if (it.status !== "pending" || denylistHits(hostOf(it.url), dl) < dl.profiles) continue;
            it.status = "completed";
            it.blocked = true;
            it.runId = queueState.runId;
            it.error = null;
            skipped++;
        }
        if (skipped) {
            queueState.note = `${skipped} link${skipped === 1 ? " was" : "s were"} skipped because the domain is already on your NextDNS denylist. Tick \"Also analyse links whose domain is already on my NextDNS denylist\" to analyse them anyway.`;
            await saveQueue();
        }
    }
    const batch = queueState.items.filter((i) => i.status === "pending").slice(0, BATCH_SIZE);
    queueState.progress = { total: batch.length, finished: 0 };
    Busy.begin("Analysing the queue");
    // The popup uses this heartbeat to tell a running scan from an interrupted one
    const beat = () => browser.storage.local.set({ [HEARTBEAT_KEY]: Date.now() });
    beat();
    const heartbeat = setInterval(beat, 5000);
    drawQueue();

    const todo = [...batch];
    const worker = async () => {
        for (let it = todo.shift(); it; it = todo.shift()) {
            try {
                await processItem(it, tools);
            } catch (e) {
                it.status = "failed";
                it.error = e.message;
            }
            queueState.progress.finished += 1;
            await saveQueue();
            drawQueue();
        }
    };
    await Promise.all(Array.from({ length: Math.min(WORKERS, batch.length) }, worker));

    queueState.running = false;
    clearInterval(heartbeat);
    await browser.storage.local.remove(HEARTBEAT_KEY);
    Busy.end("Queue finished");
    try {
        const res = await browser.runtime.sendMessage({
            action: "qsBlockCandidatesFor",
            links: batch.filter((i) => i.status === "completed" && !i.blocked).map((i) => ({
                url: i.target || i.url, flagged: i.result && (i.result.level === "high" || i.result.level === "medium"),
                chain: i.chain || [],
            })),
        });
        queueState.cands = res?.candidates || [];
    } catch {
        queueState.cands = [];
    }
    await browser.runtime.sendMessage({ action: "fetchProfiles" }).catch(() => {});
    drawQueue();
}

async function bootQueue() {
    document.getElementById("btnMarkdown").disabled = true;
    document.getElementById("btnJson").disabled = true;
    cfg = await ckConfig();
    queueState.rescanBlocked = Boolean((await browser.storage.local.get(RESCAN_KEY))[RESCAN_KEY]);
    await loadQueue();
    drawQueue();
    browser.storage.onChanged.addListener((changes, area) => {
        if (area === "local" && changes[QUEUE_KEY] && !queueState.running) {
            queueState.items = changes[QUEUE_KEY].newValue || [];
            drawQueue();
        }
    });
    if (params.get("autostart") && !queueState.running && queueState.items.some((i) => i.status === "pending")) {
        const tools = selectedQueueTools();
        const havePerm = (await Promise.all(tools.map(ckHasPermission))).every(Boolean);
        if (havePerm) startQueueRun(tools); // otherwise the button asks for permission with a click
    }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

function toMarkdown(r) {
    const o = ckOverall(r, toolState);
    const v = r.verdict;
    const lines = [
        `# Analysis: ${defang(r.target)}`, "",
        `- **Overall:** ${o.label}`,
        `- **Quick Scan:** ${v.label} (${v.score}/100)`,
        `- **Analysed:** ${r.createdAt}`,
        r.live ? `- **Live fetch:** ${r.live.captureMode}, final ${defang(r.live.final?.url || "")} (${r.live.final?.status ?? r.live.error ?? ""})` : "- **Live fetch:** not performed",
    ];
    const done = CK.TOOLS.filter((t) => toolState[t]?.status === "done");
    if (done.length) {
        lines.push("", "## Reputation checks");
        done.forEach((t) => lines.push(`- **${CK.NAMES[t]}:** ${toolState[t].headline} (${toolState[t].level})`));
    }
    lines.push("", "## Signals",
        ...v.signals.filter((s) => s.score > 0 || s.severity !== "info").map((s) => `- [${s.severity.toUpperCase()}] ${s.title}: ${s.detail}`));
    if (r.live?.hops?.length) {
        lines.push("", "## Redirect chain", "| # | Type | URL | Status | IP |", "|---|---|---|---|---|");
        r.live.hops.forEach((h, i) => lines.push(`| ${i} | ${h.kind} | ${defang(h.url)} | ${h.status ?? ""} | ${h.ip || ""} |`));
    }
    const hosts = Object.values(r.hosts || {});
    if (hosts.length) {
        lines.push("", "## Infrastructure", "| Host | IP | ASN | Registered |", "|---|---|---|---|");
        hosts.forEach((h) => lines.push(`| ${defang(h.host)} | ${(h.ips || []).join(", ")} | ${h.asn ? `AS${h.asn.asn} ${h.asn.asName || ""}` : ""} | ${fmtDate(h.rdap?.registered)} |`));
    }
    if (r.live?.final?.sha256) lines.push("", `Final response SHA-256: \`${r.live.final.sha256}\``);
    if (r.blockCandidates?.length) {
        lines.push("", "## Block candidates", ...r.blockCandidates.map((c) => `- ${defang(c.domain)} (${c.reasons.join(", ")})`));
    }
    lines.push("", "_Generated by Security Toolkit. URLs are defanged._");
    return lines.join("\n");
}

document.getElementById("btnMarkdown").addEventListener("click", (e) => {
    const button = e.currentTarget;
    if (!current) return;
    Busy.run(button, "Copying...", async () => {
        await navigator.clipboard.writeText(toMarkdown(current));
    }).then(() => {
        const old = button.textContent;
        button.textContent = "Copied";
        setTimeout(() => {
            button.textContent = old;
        }, 1500);
    });
});

document.getElementById("btnJson").addEventListener("click", () => {
    if (!current) return;
    const blob = new Blob([JSON.stringify({ report: current, checks: toolState }, null, 2)], { type: "application/json" });
    const a = el("a", { href: URL.createObjectURL(blob), download: `analysis-${hostOf(current.target) || current.id}.json` });
    document.body.append(a);
    a.click();
    setTimeout(() => {
        URL.revokeObjectURL(a.href);
        a.remove();
    }, 1000);
});

document.getElementById("btnHistory").addEventListener("click", () => {
    location.href = "report.html";
});

document.getElementById("btnQueue").addEventListener("click", () => {
    location.href = "report.html?queue=1";
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

async function bootReport() {
    cfg = await ckConfig();
    for (const t of configuredTools()) perm[t] = await ckHasPermission(t);
    toolState = await ckLoad(reportId);
    // anything still "running" from an earlier page load was interrupted
    for (const t of CK.TOOLS) {
        if (toolState[t]?.status === "running") {
            toolState[t] = { tool: t, status: "error", error: "This check was interrupted before it finished.", hint: "Run it again." };
        }
    }
    const key = REPORT_PREFIX + reportId;
    const stored = await browser.storage.local.get(key);
    render(stored[key] || null);
    if (stored[key]) maybeAutoRun(stored[key]);
    browser.storage.onChanged.addListener((changes, area) => {
        if (area === "local" && changes[key]) render(changes[key].newValue || null);
    });
    // Redraw periodically so the "interrupted" state appears if the background was suspended
    setInterval(() => {
        if (current && /running/.test(current.status)) render(current);
    }, 30000);
}

if (mode === "report") {
    bootReport();
} else {
    document.getElementById("btnMarkdown").disabled = true;
    document.getElementById("btnJson").disabled = true;
    if (mode === "queue") bootQueue();
    else renderHistory();
}
