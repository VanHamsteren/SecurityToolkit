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
        profiles = res?.profiles || [];
    } catch {
        profiles = [];
    }
    return profiles;
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
    return panel("Block domains",
        el("p", { class: "muted", style: "margin-bottom:12px" }, intro),
        cands.length ? boxes : el("p", { class: "empty" }, "No domains to suggest."),
        el("div", { class: "row", style: "margin-top:14px" }, select, blockBtn), msg);
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
    } catch (e) {
        msg.textContent = `Could not block: ${e.message}`;
        msg.className = "toast lvl-high";
    }
}

function renderStep4(r) {
    const m = stepModel(r);
    const o = ckOverall(r, toolState);
    // keep what the user already ticked when the panel is redrawn
    const touched = new Map([...region("step4").querySelectorAll(".cand input")].map((c) => [c.value, c.checked]));
    const flagged = o.level === "medium" || o.level === "high";
    const cands = (r.blockCandidates || []).map((c) => ({
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
    if (current) setRegion("step4", renderStep4(current));
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
    app.replaceChildren(
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
// Scan queue page (urlscan.io batch)
// ---------------------------------------------------------------------------

const queueState = { items: [], running: false, progress: null, cands: null, message: "" };

async function loadQueue() {
    const { urlscanQueue = [] } = await browser.storage.local.get("urlscanQueue");
    queueState.items = urlscanQueue;
}

function saveQueue() {
    return browser.storage.local.set({ urlscanQueue: queueState.items });
}

function queueStatusChip(it) {
    const labels = { pending: "Waiting", scanning: "Scanning", completed: "Done", failed: "Failed" };
    return el("span", { class: `chip chip-${it.status}` }, labels[it.status] || it.status);
}

function queueRow(it) {
    const res = it.result;
    return el("tr", {},
        el("td", {}, queueStatusChip(it)),
        el("td", { class: "url" }, defang(it.url)),
        el("td", {}, res ? [el("span", { class: `chip chip-${res.level}` }, LEVEL_TEXT[res.level]), el("div", { class: "hint muted", style: "margin-top:4px;font-size:12.5px" }, res.headline)]
            : it.error ? el("span", { class: "lvl-high", style: "font-size:13px" }, it.error)
                : it.status === "scanning" ? el("span", { class: "status-line" }, spinner(), "urlscan.io is working") : el("span", { class: "muted" }, "-")),
        el("td", {}, el("div", { class: "row" },
            it.uuid ? el("a", { class: "btn small", href: `https://urlscan.io/result/${it.uuid}/`, target: "_blank", rel: "noopener noreferrer" }, "urlscan report") : null,
            el("button", { type: "button", class: "btn small", onclick: () => browser.runtime.sendMessage({ action: "qsRescanOffline", url: it.url, run: "all" }) }, "Full analysis"),
            el("button", { type: "button", class: "btn small quiet", disabled: queueState.running && it.status === "scanning", onclick: () => removeFromQueue(it.url) }, "Remove"))));
}

async function removeFromQueue(url) {
    queueState.items = queueState.items.filter((i) => i.url !== url);
    await saveQueue();
    await browser.runtime.sendMessage({ action: "fetchProfiles" }).catch(() => {});
    drawQueue();
}

function drawQueue() {
    const items = queueState.items;
    const pending = items.filter((i) => i.status === "pending").length;
    const done = items.filter((i) => i.status === "completed");
    const flagged = done.filter((i) => i.result && (i.result.level === "high" || i.result.level === "medium")).length;
    const failed = items.filter((i) => i.status === "failed").length;
    const p = queueState.progress;
    const configured = ckIsConfigured(cfg, "urlscan");

    let control;
    if (!configured) {
        control = el("div", { class: "callout info" }, el("strong", {}, "urlscan.io is not set up. "), "Add your API key to scan the queue. ",
            el("div", { class: "row", style: "margin-top:12px" }, el("button", { type: "button", class: "btn primary", onclick: () => browser.runtime.openOptionsPage() }, "Open settings")));
    } else if (queueState.running) {
        control = el("div", { class: "stack" },
            el("div", { class: "row" },
                el("button", { type: "button", class: "btn primary is-busy", disabled: true, "aria-busy": "true" }, spinner(), "Scanning..."),
                el("span", { class: "muted" }, p ? `Submitted ${p.submitted} of ${p.total}, finished ${p.finished}. You can leave this tab open and keep browsing.` : "Starting...")),
            el("div", { class: "progress", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": String(p?.total || 1), "aria-valuenow": String(p?.finished || 0) },
                el("div", { style: `width:${p && p.total ? Math.round((p.finished / p.total) * 100) : 0}%` })));
    } else if (pending) {
        control = el("div", { class: "row" },
            el("button", { type: "button", class: "btn primary", id: "btnScanQueue", onclick: runQueue }, `Scan ${pending} waiting link${pending === 1 ? "" : "s"}`),
            el("span", { class: "muted" }, "Each link is sent to urlscan.io, 2.5 seconds apart to respect its rate limit."));
    } else {
        control = el("p", { class: "muted" }, items.length ? "Nothing waiting. Right-click more links and choose Add to scan queue." : "The queue is empty. Right-click a link, choose Security Analysis > URLScan.io > Add to scan queue.");
    }

    const blockNodes = queueState.cands && queueState.cands.length && !queueState.running
        ? [el("div", { class: "section-head", style: "margin-top:24px" }, el("div", { class: "eyebrow" }, "Step 3"), el("h2", {}, "Decide what to block"),
            el("p", {}, "Links that urlscan.io flagged are ticked. Review them before you block."))]
            .concat([blockPanel(queueState.cands, { primary: true, intro: "Domains from the queue. Popular and shared platforms are never suggested." })])
        : [];

    app.replaceChildren(
        el("div", { class: "section-head" }, el("div", { class: "eyebrow" }, "Security Toolkit"), el("h2", {}, "Scan queue"),
            el("p", {}, "Collect suspicious links during the day, scan them all at once, then block the bad ones. Three steps: add, scan, decide.")),
        el("section", { class: "card stack" },
            el("div", { class: "eyebrow" }, "Step 2 · scan"),
            el("div", { class: "row" },
                el("span", { class: "chip chip-pending" }, `${pending} waiting`),
                el("span", { class: "chip chip-done" }, `${done.length} done`),
                flagged ? el("span", { class: "chip chip-high" }, `${flagged} flagged`) : null,
                failed ? el("span", { class: "chip chip-failed" }, `${failed} failed`) : null),
            control,
            queueState.message ? el("p", { class: "toast lvl-high" }, queueState.message) : null),
        items.length ? el("section", { class: "card", style: "margin-top:16px" },
            table(["Status", "Link", "Verdict", ""], items.map(queueRow), "queue-table"),
            el("div", { class: "row", style: "margin-top:12px" },
                el("button", { type: "button", class: "btn small danger", disabled: queueState.running, onclick: clearQueueNow }, "Clear the queue"))) : null,
        ...blockNodes);
}

async function clearQueueNow() {
    if (!confirm("Remove every link from the scan queue?")) return;
    queueState.items = [];
    queueState.cands = null;
    await saveQueue();
    await browser.runtime.sendMessage({ action: "fetchProfiles" }).catch(() => {});
    drawQueue();
}

async function runQueue() {
    if (queueState.running) return;
    // permission request first: it needs the click gesture
    const granted = await ckRequestPermissions(["urlscan"]);
    if (!granted) {
        queueState.message = "urlscan.io needs permission to be contacted. Choose Allow in the prompt and try again.";
        drawQueue();
        return;
    }
    await startQueueRun();
}

async function startQueueRun() {
    queueState.running = true;
    queueState.message = "";
    queueState.cands = null;
    cfg = await ckConfig();
    await loadQueue();
    const pending = queueState.items.filter((i) => i.status === "pending");
    queueState.progress = { total: pending.length, submitted: 0, finished: 0 };
    Busy.begin("Scanning the queue");
    drawQueue();

    const waiting = [];
    for (const it of pending) {
        it.status = "scanning";
        it.error = null;
        await saveQueue();
        drawQueue();
        try {
            try {
                it.uuid = await ckUrlscanSubmit(it.url, cfg);
            } catch (e) {
                if (/rate limit/i.test(e.hint || "")) { // wait once, then retry
                    await ckSleep(30000);
                    it.uuid = await ckUrlscanSubmit(it.url, cfg);
                } else {
                    throw e;
                }
            }
            waiting.push(it);
        } catch (e) {
            it.status = "failed";
            it.error = e.hint || e.message;
            queueState.progress.finished += 1;
        }
        queueState.progress.submitted += 1;
        await saveQueue();
        drawQueue();
        await ckSleep(2500);
    }

    // poll the submitted scans round-robin so urlscan.io's result limit is respected
    const deadline = Date.now() + 180000;
    while (waiting.length && Date.now() < deadline) {
        for (const it of [...waiting]) {
            try {
                const res = await ckUrlscanFetchOnce(it.uuid, cfg);
                if (res) {
                    it.status = "completed";
                    it.result = { level: res.level, headline: res.headline };
                    waiting.splice(waiting.indexOf(it), 1);
                    queueState.progress.finished += 1;
                    await saveQueue();
                    drawQueue();
                }
            } catch (e) {
                it.status = "failed";
                it.error = e.message;
                waiting.splice(waiting.indexOf(it), 1);
                queueState.progress.finished += 1;
                await saveQueue();
                drawQueue();
            }
            await ckSleep(1000);
        }
        if (waiting.length) await ckSleep(3000);
    }
    for (const it of waiting) {
        it.status = "failed";
        it.error = "urlscan.io took too long. The scan may still finish: open the urlscan report.";
        queueState.progress.finished += 1;
    }
    await saveQueue();

    queueState.running = false;
    Busy.end("Queue finished");
    try {
        const res = await browser.runtime.sendMessage({
            action: "qsBlockCandidatesFor",
            links: queueState.items.filter((i) => i.status === "completed").map((i) => ({
                url: i.url, flagged: i.result && (i.result.level === "high" || i.result.level === "medium"),
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
    await loadQueue();
    drawQueue();
    browser.storage.onChanged.addListener((changes, area) => {
        if (area === "local" && changes.urlscanQueue && !queueState.running) {
            queueState.items = changes.urlscanQueue.newValue || [];
            drawQueue();
        }
    });
    if (params.get("autostart") && !queueState.running && ckIsConfigured(cfg, "urlscan")
        && queueState.items.some((i) => i.status === "pending") && (await ckHasPermission("urlscan"))) {
        startQueueRun();
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
