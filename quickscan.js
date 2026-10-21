/* global browser, notifyError, sendToUrlscan, sendToVirusTotal, addToNextDnsList, nextDnsProfiles */
/**
 * Security Toolkit - Quick Scan engine
 *
 * A lightweight, self-contained URL analysis that runs inside the extension,
 * next to the external scanners (urlscan.io, VirusTotal, ...).
 *
 * Stage 1 - offline: URL dissection (wrapper unwrapping, base64 decoding,
 *   tracking IDs, punycode, brand look-alikes) plus DNS, ASN and RDAP
 *   enrichment. This stage never contacts the target server.
 *
 * Stage 2 - live (user-initiated): fetches the URL from the user's own
 *   connection, without cookies, Origin or Referer. The redirect chain,
 *   server IPs and TLS certificates are captured with webRequest. The
 *   response is analysed as TEXT only: nothing is rendered and no remote
 *   code is ever executed (DOMParser documents are inert).
 *
 * Mozilla constraints honoured:
 *   - <all_urls>, webRequest and webRequestBlocking are optional permissions,
 *     requested from a user gesture on the report page only when needed.
 *   - No eval / remote code; fetched content is data, never code.
 *   - Report UI builds DOM with textContent (no innerHTML with page data).
 */

const QS_CONFIG = {
    MAX_BODY_BYTES: 2 * 1024 * 1024,
    FETCH_TIMEOUT_MS: 15000,
    MAX_CLIENT_HOPS: 5,
    MAX_REPORTS: 25,
    MAX_ENRICH_HOSTS: 10,
    INDEX_KEY: "quickScanIndex",
    REPORT_PREFIX: "qs_",
    LIVE_PERMISSIONS: {
        permissions: ["webRequest", "webRequestBlocking"],
        origins: ["<all_urls>"],
    },
};

// ---------------------------------------------------------------------------
// Reference data
// ---------------------------------------------------------------------------

/** Second-level labels under which registrations happen (no full PSL needed) */
const QS_MULTI_SLD = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "co.nz", "org.nz", "com.br", "net.br",
    "com.tr", "co.jp", "ne.jp", "or.jp", "co.za", "com.cn", "net.cn",
    "com.mx", "co.in", "net.in", "co.id", "or.id", "web.id", "my.id",
    "com.sg", "com.my", "com.hk", "co.kr", "com.ar", "com.pl", "com.ua",
    "com.tw", "co.il", "com.sa", "com.ng", "com.pk", "com.vn", "com.ph",
    "co.th", "com.eg", "com.co", "com.pe", "com.ec", "com.bd", "com.np",
]);

/** TLDs heavily over-represented in spam/phishing (weak signal on its own) */
const QS_SUSPICIOUS_TLDS = new Set([
    "zip", "mov", "xyz", "top", "click", "shop", "icu", "cfd", "sbs", "lol",
    "buzz", "rest", "monster", "quest", "cyou", "bond", "help", "pw", "tk",
    "ml", "ga", "cf", "gq", "work", "support", "link", "country", "kim",
    "men", "loan", "win", "bid", "review", "date", "download", "racing",
    "stream", "gdn", "cam", "beauty", "hair", "skin", "makeup", "autos",
    "boats", "homes", "yachts", "mom", "lat", "best", "fit", "life", "live",
    "online", "site", "store", "website", "space", "fun", "today", "world",
]);

/** Well-known benign sites: landing here from an unknown domain suggests cloaking */
const QS_POPULAR_DOMAINS = new Set([
    "google.com", "youtube.com", "w3schools.com", "wikipedia.org", "microsoft.com",
    "bing.com", "yahoo.com", "amazon.com", "apple.com", "cloudflare.com",
    "example.com", "example.org", "github.com", "stackoverflow.com", "office.com",
    "live.com", "outlook.com", "facebook.com", "instagram.com", "linkedin.com",
    "twitter.com", "x.com", "reddit.com", "netflix.com", "nu.nl", "bol.com",
    "duckduckgo.com", "baidu.com", "adobe.com", "paypal.com", "mozilla.org",
    "msn.com", "booking.com", "ebay.com", "cnn.com", "bbc.com", "bbc.co.uk",
    "nos.nl", "google.nl", "marktplaats.nl", "wordpress.org", "w3.org",
    "tiktok.com", "whatsapp.com", "zoom.us", "dropbox.com", "spotify.com",
]);

/** Brand keyword -> legitimate apex domains */
const QS_BRANDS = {
    microsoft: ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com",
        "sharepoint.com", "onedrive.com", "windows.net", "azure.com", "msauth.net", "msftauth.net",
        "office365.com", "microsoft365.com", "skype.com", "xbox.com", "bing.com", "msn.com",
        "office.net", "sharepointonline.com", "azureedge.net", "aka.ms"],
    office365: null, office: null, outlook: null, sharepoint: null, onedrive: null, msonline: null,
    docusign: ["docusign.com", "docusign.net"],
    adobe: ["adobe.com", "adobelogin.com", "adobe.io"],
    paypal: ["paypal.com", "paypal.me", "paypalobjects.com"],
    apple: ["apple.com", "icloud.com", "apple.news"],
    icloud: null,
    netflix: ["netflix.com", "nflxext.com", "netflix.net"],
    dhl: ["dhl.com", "dhl.nl", "dhl.de", "dhlparcel.nl", "dhl.be"],
    postnl: ["postnl.nl", "postnl.com", "postnl.be"],
    rabobank: ["rabobank.nl", "rabobank.com"],
    abnamro: ["abnamro.nl", "abnamro.com"],
    belastingdienst: ["belastingdienst.nl"],
    digid: ["digid.nl"],
    ziggo: ["ziggo.nl"],
    marktplaats: ["marktplaats.nl"],
    wetransfer: ["wetransfer.com", "we.tl"],
    dropbox: ["dropbox.com", "dropboxusercontent.com", "db.tt"],
    amazon: ["amazon.com", "amazon.nl", "amazon.de", "amazon.co.uk", "amazonaws.com", "a2z.com"],
    coinbase: ["coinbase.com"],
    binance: ["binance.com"],
    metamask: ["metamask.io"],
    facebook: ["facebook.com", "fb.com", "meta.com", "facebook.net"],
    instagram: ["instagram.com"],
    whatsapp: ["whatsapp.com", "whatsapp.net", "wa.me"],
    linkedin: ["linkedin.com", "lnkd.in"],
    booking: ["booking.com", "bstatic.com"],
    google: ["google.com", "google.nl", "gmail.com", "googleusercontent.com", "googleapis.com",
        "gstatic.com", "youtube.com", "goo.gl", "g.co", "google.be", "google.de", "google.co.uk"],
    gmail: null,
};
// Aliases share the list of their parent brand
for (const alias of ["office365", "office", "outlook", "sharepoint", "onedrive", "msonline"]) {
    QS_BRANDS[alias] = QS_BRANDS.microsoft;
}
QS_BRANDS.icloud = QS_BRANDS.apple;
QS_BRANDS.gmail = QS_BRANDS.google;

/** Short brands that only match as an exact hostname token */
const QS_EXACT_TOKEN_BRANDS = { ing: ["ing.nl", "ing.com", "ing.be", "ing.de"], kpn: ["kpn.com", "kpn.nl"], ups: ["ups.com"], bol: ["bol.com"], asn: ["asnbank.nl"], sns: ["snsbank.nl"] };

/** Brand names as they appear in page text, with the brand key they map to */
const QS_PAGE_BRANDS = [
    [/\bMicrosoft\b|\bOffice 365\b|\bMicrosoft 365\b|\bOutlook\b|\bSharePoint\b|\bOneDrive\b/i, "microsoft"],
    [/\bDocuSign\b/i, "docusign"], [/\bAdobe\b/i, "adobe"], [/\bPayPal\b/i, "paypal"],
    [/\bApple ID\b|\biCloud\b/i, "apple"], [/\bNetflix\b/i, "netflix"], [/\bDHL\b/, "dhl"],
    [/\bPostNL\b/i, "postnl"], [/\bING\b/, "ing"], [/\bRabobank\b/i, "rabobank"],
    [/\bABN ?AMRO\b/i, "abnamro"], [/\bBelastingdienst\b/i, "belastingdienst"], [/\bDigiD\b/i, "digid"],
    [/\bKPN\b/, "kpn"], [/\bZiggo\b/i, "ziggo"], [/\bWeTransfer\b/i, "wetransfer"],
    [/\bDropbox\b/i, "dropbox"], [/\bCoinbase\b/i, "coinbase"], [/\bMetaMask\b/i, "metamask"],
    [/\bBinance\b/i, "binance"], [/\bMarktplaats\b/i, "marktplaats"], [/\bGmail\b|\bGoogle Account\b/i, "google"],
];

/** Free hosting / tunnelling platforms frequently abused for phishing pages */
const QS_PLATFORMS = [
    "workers.dev", "pages.dev", "r2.dev", "web.app", "firebaseapp.com", "firebasestorage.googleapis.com",
    "blob.core.windows.net", "web.core.windows.net", "glitch.me", "ngrok.io", "ngrok-free.app", "ngrok.app",
    "trycloudflare.com", "vercel.app", "netlify.app", "github.io", "onrender.com", "replit.app", "repl.co",
    "weebly.com", "wixsite.com", "square.site", "godaddysites.com", "webflow.io", "jimdosite.com",
    "000webhostapp.com", "herokuapp.com", "azurewebsites.net", "appspot.com", "ipfs.io", "dweb.link",
    "storage.googleapis.com", "s3.amazonaws.com", "amplifyapp.com", "framer.app", "notion.site",
    "sites.google.com", "forms.gle", "typedream.app", "carrd.co", "surge.sh", "duckdns.org", "ddns.net",
];

const QS_SHORTENERS = new Set([
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "rebrand.ly", "cutt.ly", "t.ly", "rb.gy", "ow.ly",
    "buff.ly", "shorturl.at", "s.id", "lnkd.in", "goo.gl", "tiny.cc", "v.gd", "qrco.de", "urlz.fr",
]);

/** Text indicators in page source: [regex, id, severity, score, title, detail] */
const QS_SOURCE_INDICATORS = [
    [/api\.telegram\.org\/bot/i, "exfil-telegram", "high", 35, "Sends data to a Telegram bot",
        "The page source contains the Telegram Bot API. Phishing kits commonly forward stolen credentials to a Telegram chat."],
    [/discord(?:app)?\.com\/api\/webhooks/i, "exfil-discord", "high", 35, "Sends data to a Discord webhook",
        "Discord webhooks are a common drop point for stolen credentials."],
    [/formspree\.io|getform\.io|submit-form\.com|formsubmit\.co|web3forms\.com|formcarry\.com|usebasin\.com|script\.google\.com\/macros/i,
        "exfil-formservice", "medium", 15, "Uses a third-party form backend",
        "Form data goes to a hosted form service instead of the site's own server, a cheap way for kits to collect credentials."],
    [/ipapi\.co|ipinfo\.io|ip-api\.com|api\.ipify\.org|geoplugin\.net|ipwho\.is|ipdata\.co|ip2location|extreme-ip-lookup|freegeoip|ipgeolocation\.io/i,
        "geo-lookup", "medium", 15, "Looks up the visitor's IP / location",
        "Used to target specific countries or to hide the real content from scanners and researchers (cloaking)."],
    [/aadcdn\.msftauth\.net|aadcdn\.msauth\.net|logincdn\.msauth\.net|login\.microsoftonline\.com|login\.live\.com/i,
        "ms-assets", "medium", 10, "References Microsoft sign-in infrastructure",
        "Normal on Microsoft's own pages. On any other domain it usually means a cloned Microsoft login page or an adversary-in-the-middle (AiTM) kit."],
    [/challenges\.cloudflare\.com\/turnstile|hcaptcha\.com\/1\/api|google\.com\/recaptcha|recaptcha\/api\.js/i,
        "captcha-gate", "low", 5, "CAPTCHA gate",
        "Phishing sites increasingly put a CAPTCHA in front of the real page so automated scanners never see it."],
    [/navigator\.webdriver|(?:^|[;{}\s])debugger\s*;|devtools\s*\.\s*(?:open|isOpen)|devtoolschange|window\.outerWidth\s*-\s*window\.innerWidth/i,
        "anti-analysis", "medium", 10, "Anti-analysis checks",
        "The script checks for automation (webdriver), developer tools or uses debugger traps to frustrate analysis."],
    [/contextmenu[^;]{0,80}preventDefault|oncontextmenu\s*=\s*["']?\s*return false|keyCode\s*==+\s*123|key\s*===?\s*["']F12["']|ctrlKey\s*&&[^;]{0,40}(?:85|["']u["'])/i,
        "block-inspect", "medium", 10, "Blocks right-click / F12 / view-source",
        "Legitimate sites rarely prevent users from inspecting the page."],
];

const QS_OBFUSCATION = [
    [/\beval\s*\(/g, "eval()"], [/\batob\s*\(/g, "atob()"], [/\bunescape\s*\(/g, "unescape()"],
    [/String\.fromCharCode/g, "String.fromCharCode"], [/document\.write\s*\(/g, "document.write()"],
    [/\\x[0-9a-f]{2}/gi, "hex escapes", 50], [/_0x[a-f0-9]{4,6}/gi, "obfuscator.io identifiers", 20],
    [/[A-Za-z0-9+/]{800,}={0,2}/g, "long base64 blobs"],
];

const QS_TRACKING_PARAMS = new Set([
    "ei", "eid", "uid", "rid", "cid", "li", "lid", "email", "e", "mail", "recipient", "subscriber",
    "sid", "token", "mid", "user", "usr", "trk", "tracking", "clickid", "click_id", "subid", "sub_id",
    "aff_id", "contact", "contactid", "lead", "leadid",
]);

const QS_DANGEROUS_EXT = /\.(exe|scr|msi|msix|appx|iso|img|vhdx?|lnk|js|jse|vbs|vbe|hta|wsf|bat|cmd|ps1|jar|apk|dll|cpl|one|zip|rar|7z|cab|gz|tgz|html?|svg|shtml|xll|xlsm|docm|pptm)$/i;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function qsIsIp(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

/** Registrable domain without a full Public Suffix List */
function qsApex(host) {
    if (!host) return "";
    host = host.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
    if (qsIsIp(host)) return host;
    const labels = host.split(".");
    if (labels.length <= 2) return host;
    const lastTwo = labels.slice(-2).join(".");
    return QS_MULTI_SLD.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

/** True when host equals domain or is a subdomain of it */
function qsHostIn(host, domain) {
    host = (host || "").toLowerCase();
    return host === domain || host.endsWith(`.${domain}`);
}

function qsPlatformOf(host) {
    return QS_PLATFORMS.find((p) => qsHostIn(host, p)) || null;
}

function qsSafeDecode(s) {
    try {
        return decodeURIComponent(s.replace(/\+/g, " "));
    } catch {
        return s;
    }
}

/** Decode a base64 / base64url string if the result is mostly printable text */
function qsTryBase64(s) {
    if (!s || s.length < 12 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return null;
    // Pure hex or pure digits are IDs, not base64
    if (/^[0-9a-f]+$/i.test(s) || /^\d+$/.test(s)) return null;
    try {
        let b = s.replace(/-/g, "+").replace(/_/g, "/");
        while (b.length % 4) b += "=";
        const bin = atob(b);
        let printable = 0;
        for (let i = 0; i < bin.length; i++) {
            const c = bin.charCodeAt(i);
            if ((c >= 32 && c < 127) || c === 10 || c === 13 || c === 9) printable++;
        }
        if (bin.length < 4 || printable / bin.length < 0.9) return null;
        return bin;
    } catch {
        return null;
    }
}

function qsFindEmails(text) {
    const m = (text || "").match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}/gi) || [];
    return [...new Set(m.map((e) => e.toLowerCase()))].filter((e) => !/\.(png|jpe?g|gif|svg|webp|css|js)$/.test(e));
}

function qsSignal(id, severity, score, title, detail, extra = {}) {
    return { id, severity, score, title, detail, ...extra };
}

function qsDaysSince(dateValue) {
    const t = typeof dateValue === "number" ? dateValue : Date.parse(dateValue);
    if (!Number.isFinite(t)) return null;
    return Math.floor((Date.now() - t) / 86400000);
}

/** Brand impersonated by a hostname, or null */
function qsBrandInHost(host) {
    const apex = qsApex(host);
    const tokens = host.toLowerCase().split(/[.-]/).filter(Boolean);
    for (const [brand, legit] of Object.entries(QS_BRANDS)) {
        if (!legit) continue;
        const hit = tokens.some((t) => t === brand || (brand.length >= 5 && t.includes(brand)));
        if (hit && !legit.some((d) => qsHostIn(host, d) || apex === d)) return brand;
    }
    for (const [brand, legit] of Object.entries(QS_EXACT_TOKEN_BRANDS)) {
        // Exact token, excluding the TLD itself (e.g. ".ing" would be a TLD)
        if (tokens.slice(0, -1).includes(brand) && !legit.some((d) => qsHostIn(host, d))) return brand;
    }
    return null;
}

function qsBrandLegit(brand) {
    return QS_BRANDS[brand] || QS_EXACT_TOKEN_BRANDS[brand] || [];
}

// ---------------------------------------------------------------------------
// Stage 0: input normalisation and link-wrapper unwrapping
// ---------------------------------------------------------------------------

function qsNormalizeInput(text) {
    let s = (text || "").trim().replace(/^<|>$/g, "").replace(/^["']|["']$/g, "");
    // Re-fang common defanging: hxxp, [.], (.), [:]
    s = s.replace(/^hxxp/i, "http").replace(/\[\.\]|\(\.\)|\{\.\}/g, ".").replace(/\[:\]/g, ":");
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
    return new URL(s).href;
}

/** Unwrap Safe Links, Proofpoint, Google redirects etc. Returns {url, steps} */
function qsUnwrapUrl(raw) {
    const steps = [];
    let cur = raw;
    for (let i = 0; i < 6; i++) {
        let u;
        try {
            u = new URL(cur);
        } catch {
            break;
        }
        const h = u.hostname.toLowerCase();
        let next = null;
        let via = null;
        if (h.endsWith("safelinks.protection.outlook.com")) {
            next = u.searchParams.get("url");
            via = "Microsoft Defender Safe Links";
        } else if (/(^|\.)google\.[a-z.]{2,6}$/.test(h) && u.pathname === "/url") {
            next = u.searchParams.get("q") || u.searchParams.get("url");
            via = "Google redirect";
        } else if (h === "urldefense.com" && u.pathname.startsWith("/v3/__")) {
            const m = cur.match(/\/v3\/__(.+?)__;/);
            next = m ? m[1] : null;
            via = "Proofpoint URL Defense v3";
        } else if (h === "urldefense.proofpoint.com" && u.pathname.startsWith("/v2/url")) {
            const p = u.searchParams.get("u");
            next = p ? qsSafeDecode(p.replace(/-/g, "%").replace(/_/g, "/")) : null;
            via = "Proofpoint URL Defense v2";
        } else if (h.endsWith("linkprotect.cudasvc.com")) {
            next = u.searchParams.get("a");
            via = "Barracuda Link Protection";
        } else if (h === "l.facebook.com" || h === "lm.facebook.com") {
            next = u.searchParams.get("u");
            via = "Facebook link shim";
        } else if (h.endsWith("protect.mimecast.com") || h.endsWith("mimecastprotect.com")) {
            break; // Mimecast tokens can't be resolved offline
        }
        if (!next) break;
        try {
            next = new URL(next).href;
        } catch {
            break;
        }
        steps.push({ from: cur, via });
        cur = next;
    }
    return { url: cur, steps };
}

// ---------------------------------------------------------------------------
// Stage 1a: offline URL analysis
// ---------------------------------------------------------------------------

function qsAnalyzeUrl(href) {
    const u = new URL(href);
    const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    const apex = qsApex(host);
    const tld = qsIsIp(host) ? "" : host.split(".").pop();
    const signals = [];
    const decoded = [];
    const tracking = [];
    const embeddedUrls = [];

    // Collect candidate strings: path segments, query values, fragment
    const parts = [];
    u.pathname.split("/").filter(Boolean).forEach((seg) => parts.push({ where: "path", key: null, value: qsSafeDecode(seg) }));
    for (const [k, v] of u.searchParams) parts.push({ where: "query", key: k, value: v });
    if (u.hash.length > 1) parts.push({ where: "fragment", key: null, value: qsSafeDecode(u.hash.slice(1)) });

    const inspectKv = (key, value, origin) => {
        if (!key) return;
        const k = key.toLowerCase();
        if (QS_TRACKING_PARAMS.has(k) && /^[A-Za-z0-9_.@%+-]{3,}$/.test(value)) {
            tracking.push({ key, value, origin });
        }
    };

    for (const p of parts) {
        inspectKv(p.key, p.value, p.where);
        if (/^https?:\/\//i.test(p.value)) embeddedUrls.push(p.value);
        const b = qsTryBase64(p.value);
        if (b) {
            decoded.push({ where: p.where, key: p.key, raw: p.value, decoded: b });
            if (/^https?:\/\//i.test(b)) embeddedUrls.push(b.trim());
            // Decoded query strings: ?a=1&b=2 or a=1&b=2
            if (/[=&]/.test(b)) {
                const qs = b.replace(/^[^?]*\?/, "");
                try {
                    for (const [k, v] of new URLSearchParams(qs)) {
                        inspectKv(k, v, "base64");
                        if (/^https?:\/\//i.test(v)) embeddedUrls.push(v);
                    }
                } catch {
                    /* not a query string */
                }
            }
        }
    }

    const emails = qsFindEmails([qsSafeDecode(href), ...decoded.map((d) => d.decoded)].join(" "));

    // --- Signals ---
    if (qsIsIp(host)) {
        signals.push(qsSignal("ip-host", "medium", 20, "Link points to a bare IP address",
            "Legitimate services almost always use a domain name."));
    }
    if (host.split(".").some((l) => l.startsWith("xn--"))) {
        signals.push(qsSignal("punycode", "medium", 15, "Internationalised (punycode) domain",
            "Punycode domains can imitate familiar names with look-alike characters (homograph attack)."));
    }
    if (u.username || u.password) {
        signals.push(qsSignal("userinfo", "medium", 20, "URL contains an '@' credential part",
            `Everything before '@' is ignored by the browser, the real host is ${host}. A classic trick to make a link look like another site.`));
    }
    if (QS_SUSPICIOUS_TLDS.has(tld)) {
        signals.push(qsSignal("tld", "low", 8, `High-abuse top-level domain .${tld}`,
            "Cheap TLDs like this one are over-represented in spam and phishing. Weak signal on its own."));
    }
    if (host.split(".").length >= 5 || host.length > 50) {
        signals.push(qsSignal("long-host", "low", 5, "Unusually long or deep hostname",
            "Long hostnames are used to push the real domain out of view, especially on mobile."));
    }
    const brand = qsBrandInHost(host);
    if (brand) {
        signals.push(qsSignal("brand-host", "high", 30, `Domain name uses the brand "${brand}"`,
            `The hostname contains "${brand}" but is not one of the brand's own domains (${qsBrandLegit(brand).slice(0, 4).join(", ")}...).`));
    }
    const platform = qsPlatformOf(host);
    if (platform) {
        signals.push(qsSignal("platform", "low", 8, `Hosted on a free platform (${platform})`,
            "Free hosting and tunnelling platforms are popular for short-lived phishing pages."));
    }
    if (QS_SHORTENERS.has(host)) {
        signals.push(qsSignal("shortener", "low", 5, `URL shortener (${host})`, "Hides the real destination until it is followed."));
    }
    if (u.protocol === "http:") {
        signals.push(qsSignal("plain-http", "info", 0, "Plain HTTP link", "Common for mailing-list click trackers and redirectors; not a signal by itself."));
    }
    if (tracking.length || emails.length) {
        signals.push(qsSignal("personalised", "medium", 10, "Personalised link (recipient tracking)",
            `The link carries ${emails.length ? "an e-mail address" : "recipient/campaign identifiers"} (${[...emails, ...tracking.map((t) => `${t.key}=${t.value}`)].slice(0, 4).join(", ")}). ` +
            "Opening it, or fetching it live, can tell the sender that this mailbox is real and read."));
    }
    if (embeddedUrls.length) {
        signals.push(qsSignal("embedded-url", "low", 5, "Link carries another URL inside it",
            `Open-redirect or tracker style link. Embedded target: ${embeddedUrls[0]}`));
    }

    return {
        href, scheme: u.protocol.replace(":", ""), host, apex, tld, port: u.port || null,
        path: u.pathname, query: [...u.searchParams].map(([k, v]) => ({ k, v })),
        fragment: u.hash ? u.hash.slice(1) : "", decoded, tracking, emails,
        embeddedUrls: [...new Set(embeddedUrls)], brand, platform, signals,
    };
}

// ---------------------------------------------------------------------------
// Stage 1b: DNS / ASN / RDAP enrichment (CORS-enabled public services)
// ---------------------------------------------------------------------------

const qsEnrichCache = new Map();

async function qsDns(name, type) {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, {
        credentials: "omit",
    });
    if (!r.ok) throw new Error(`DNS HTTP ${r.status}`);
    return r.json();
}

function qsTxt(data) {
    return (data || "").replace(/^"|"$/g, "").replace(/"\s*"/g, "");
}

async function qsAsnForIp(ip) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return null;
    const rev = ip.split(".").reverse().join(".");
    const origin = await qsDns(`${rev}.origin.asn.cymru.com`, "TXT");
    const line = qsTxt(origin.Answer?.find((a) => a.type === 16)?.data);
    if (!line) return null;
    const [asn, prefix, country] = line.split("|").map((s) => s.trim());
    let asName = null;
    try {
        const asInfo = await qsDns(`AS${asn.split(" ")[0]}.asn.cymru.com`, "TXT");
        const l2 = qsTxt(asInfo.Answer?.find((a) => a.type === 16)?.data);
        asName = l2 ? l2.split("|").pop().trim() : null;
    } catch {
        /* AS name is optional */
    }
    return { asn: asn.split(" ")[0], prefix, country, asName };
}

async function qsRdap(apex) {
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(apex)}`, {
        headers: { Accept: "application/rdap+json" },
        credentials: "omit",
    });
    if (r.status === 404) return { found: false };
    if (!r.ok) return { error: `HTTP ${r.status}` };
    const d = await r.json();
    const ev = (a) => d.events?.find((e) => e.eventAction === a)?.eventDate || null;
    const registrar = d.entities?.find((e) => e.roles?.includes("registrar"));
    const fn = registrar?.vcardArray?.[1]?.find((v) => v[0] === "fn")?.[3] || registrar?.handle || null;
    const registered = ev("registration");
    return {
        found: true, registered, updated: ev("last changed"), expires: ev("expiration"),
        ageDays: registered ? qsDaysSince(registered) : null, registrar: fn, status: d.status || [],
    };
}

async function qsEnrichHost(host) {
    if (qsEnrichCache.has(host)) return qsEnrichCache.get(host);
    const job = (async () => {
        const out = { host, apex: qsApex(host), ips: [], cname: [], ns: [], resolved: null };
        try {
            if (qsIsIp(host)) {
                out.ips = [host];
                out.resolved = true;
            } else {
                const a = await qsDns(host, "A");
                out.resolved = a.Status === 0 && !!a.Answer?.length;
                out.nxdomain = a.Status === 3;
                out.cname = (a.Answer || []).filter((x) => x.type === 5).map((x) => x.data.replace(/\.$/, ""));
                out.ips = (a.Answer || []).filter((x) => x.type === 1).map((x) => x.data);
                const ns = await qsDns(out.apex, "NS").catch(() => null);
                out.ns = (ns?.Answer || []).filter((x) => x.type === 2).map((x) => x.data.replace(/\.$/, "").toLowerCase());
            }
            if (out.ips[0]) out.asn = await qsAsnForIp(out.ips[0]).catch(() => null);
        } catch (e) {
            out.error = e.message;
        }
        if (!qsIsIp(host)) out.rdap = await qsRdap(out.apex).catch((e) => ({ error: e.message }));
        return out;
    })();
    qsEnrichCache.set(host, job);
    setTimeout(() => qsEnrichCache.delete(host), 10 * 60 * 1000);
    return job;
}

function qsEnrichmentSignals(hosts, primaryHost) {
    const signals = [];
    const seenApex = new Set();
    for (const h of Object.values(hosts)) {
        if (!h || seenApex.has(h.apex) || QS_POPULAR_DOMAINS.has(h.apex)) continue;
        seenApex.add(h.apex);
        const age = h.rdap?.ageDays;
        if (age != null && age < 30) {
            signals.push(qsSignal(`young-${h.apex}`, "high", 25, `${h.apex} was registered ${age} day(s) ago`,
                "Brand-new domains are the norm for phishing campaigns; most are burned within days."));
        } else if (age != null && age < 180) {
            signals.push(qsSignal(`young-${h.apex}`, "medium", 12, `${h.apex} is only ${Math.round(age / 30)} month(s) old`,
                "Recently registered domains carry more risk."));
        }
        if (h.host === primaryHost && h.nxdomain) {
            signals.push(qsSignal("nxdomain", "info", 0, `${h.host} does not resolve`,
                "The domain no longer exists in DNS: taken down, expired or not yet live. A live fetch will fail."));
        }
    }
    return signals;
}

// ---------------------------------------------------------------------------
// Stage 2a: static HTML analysis (text only, nothing executes)
// ---------------------------------------------------------------------------

function qsResolve(href, base) {
    try {
        return new URL(href, base).href;
    } catch {
        return null;
    }
}

/** Find client-side redirect targets in raw HTML/JS source */
function qsFindJsRedirects(source, base) {
    const found = [];
    const patterns = [
        /(?:window\.|document\.|top\.|self\.|parent\.)?location(?:\.href)?\s*=\s*["'`]([^"'`]{4,2000})["'`]/gi,
        /location\.(?:replace|assign)\(\s*["'`]([^"'`]{4,2000})["'`]\s*\)/gi,
        /window\.open\(\s*["'`]([^"'`]{4,2000})["'`]/gi,
    ];
    for (const re of patterns) {
        let m;
        while ((m = re.exec(source)) && found.length < 10) {
            const abs = qsResolve(m[1], base);
            if (abs && /^https?:/i.test(abs)) found.push(abs);
        }
    }
    return [...new Set(found)];
}

function qsAnalyzeHtml(html, pageUrl) {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const pageHost = new URL(pageUrl).hostname.toLowerCase();
    const pageApex = qsApex(pageHost);
    const signals = [];
    const refDomains = {};
    const addRef = (url, kind) => {
        try {
            const h = new URL(url).hostname.toLowerCase();
            if (!h) return;
            refDomains[h] = refDomains[h] || { count: 0, kinds: new Set() };
            refDomains[h].count++;
            refDomains[h].kinds.add(kind);
        } catch {
            /* ignore */
        }
    };

    const title = (doc.querySelector("title")?.textContent || "").trim().slice(0, 300);
    const bodyText = (doc.body?.textContent || "").replace(/\s+/g, " ").trim();
    const scripts = [...doc.querySelectorAll("script")];
    const inlineJs = scripts.filter((s) => !s.getAttribute("src")).map((s) => s.textContent || "").join("\n");
    const externalScripts = scripts.map((s) => s.getAttribute("src")).filter(Boolean)
        .map((s) => qsResolve(s, pageUrl)).filter(Boolean);
    externalScripts.forEach((s) => addRef(s, "script"));
    doc.querySelectorAll("link[href]").forEach((l) => {
        const r = qsResolve(l.getAttribute("href"), pageUrl);
        if (r) addRef(r, "link");
    });
    doc.querySelectorAll("img[src]").forEach((i) => {
        const r = qsResolve(i.getAttribute("src"), pageUrl);
        if (r && /^https?:/.test(r)) addRef(r, "img");
    });

    // --- Meta refresh ---
    let metaRefresh = null;
    const meta = [...doc.querySelectorAll("meta[http-equiv]")].find((m) => /refresh/i.test(m.getAttribute("http-equiv")));
    if (meta) {
        const c = meta.getAttribute("content") || "";
        const m = c.match(/url\s*=\s*['"]?([^'";]+)/i);
        if (m) metaRefresh = qsResolve(m[1].trim(), pageUrl);
    }
    const jsRedirects = qsFindJsRedirects(inlineJs, pageUrl);

    // --- Forms ---
    const forms = [...doc.querySelectorAll("form")].slice(0, 20).map((f) => {
        const actionRaw = f.getAttribute("action");
        const action = actionRaw ? qsResolve(actionRaw, pageUrl) : pageUrl;
        if (action) addRef(action, "form");
        const inputs = [...f.querySelectorAll("input, select, textarea")].slice(0, 40).map((i) => ({
            type: (i.getAttribute("type") || i.tagName).toLowerCase(),
            name: i.getAttribute("name") || i.getAttribute("id") || "",
            value: i.getAttribute("type") === "hidden" ? (i.getAttribute("value") || "").slice(0, 120) : undefined,
        }));
        return { action, method: (f.getAttribute("method") || "get").toLowerCase(), inputs };
    });
    // Password fields outside forms count too (JS-driven login pages)
    const passwordFields = doc.querySelectorAll('input[type="password"]').length;
    const allInputs = [...doc.querySelectorAll("input")].map((i) => `${i.getAttribute("type") || ""} ${i.getAttribute("name") || ""} ${i.getAttribute("id") || ""} ${i.getAttribute("autocomplete") || ""} ${i.getAttribute("placeholder") || ""}`.toLowerCase());
    const hasCardFields = allInputs.some((s) => /cc-number|card.?num|cardnumber|\bcvv\b|\bcvc\b|cc-exp|expiry/.test(s));
    const hasOtpFields = allInputs.some((s) => /one-time-code|\botp\b|2fa|mfa|sms.?code|verification.?code/.test(s));

    // --- iframes ---
    const iframes = [...doc.querySelectorAll("iframe[src]")].map((f) => qsResolve(f.getAttribute("src"), pageUrl))
        .filter((f) => f && /^https?:/i.test(f));
    iframes.forEach((f) => addRef(f, "iframe"));

    // --- Brand impersonation on the page ---
    const brandText = `${title} ${bodyText.slice(0, 6000)}`;
    const pageBrands = QS_PAGE_BRANDS.filter(([re]) => re.test(brandText)).map(([, b]) => b);
    const foreignBrands = [...new Set(pageBrands)].filter((b) => !qsBrandLegit(b).some((d) => qsHostIn(pageHost, d)));

    // --- Signals ---
    if (passwordFields > 0) {
        if (foreignBrands.length) {
            signals.push(qsSignal("brand-login", "high", 40, `Login form imitating ${foreignBrands.join(", ")}`,
                `The page asks for a password and presents itself as ${foreignBrands.join("/")}, but is hosted on ${pageApex}. This is the core pattern of credential phishing.`));
        } else {
            signals.push(qsSignal("password-field", "medium", 15, "Page asks for a password",
                `A password field on ${pageApex}. Fine for a site you have an account with, suspicious when reached from an unsolicited mail.`));
        }
    } else if (foreignBrands.length && title && foreignBrands.some((b) => QS_PAGE_BRANDS.find(([, k]) => k === b)[0].test(title))) {
        signals.push(qsSignal("brand-title", "medium", 10, `Page title mentions ${foreignBrands.join(", ")}`,
            `The page presents itself as ${foreignBrands.join("/")} while hosted on ${pageApex}.`));
    }
    if (hasCardFields) {
        signals.push(qsSignal("card-fields", "high", 25, "Asks for payment card details",
            "Card number / CVC fields. Typical for parcel-fee, toll and subscription scams."));
    }
    if (hasOtpFields && !pageBrands.length) {
        signals.push(qsSignal("otp-fields", "medium", 10, "Asks for a one-time / MFA code",
            "Real-time phishing kits relay MFA codes to log in as the victim."));
    }
    for (const f of forms) {
        if (!f.action) continue;
        let aHost = "";
        try {
            aHost = new URL(f.action).hostname.toLowerCase();
        } catch {
            continue;
        }
        if (aHost && qsApex(aHost) !== pageApex) {
            signals.push(qsSignal(`form-ext-${aHost}`, "medium", 15, `Form submits to another domain (${aHost})`,
                "Data typed into this page is sent to a different domain than the one shown."));
        }
        const prefill = f.inputs.find((i) => i.type === "hidden" && /@/.test(i.value || ""));
        if (prefill) {
            signals.push(qsSignal("prefill-email", "medium", 10, "E-mail address pre-filled in a hidden field",
                "The page already knows who you are; personalised phishing pages do this to look convincing."));
        }
    }
    if (iframes.some((f) => qsApex(new URL(f).hostname) !== pageApex)) {
        signals.push(qsSignal("ext-iframe", "low", 8, "Embeds another site in an iframe",
            `Content is framed from: ${[...new Set(iframes.map((f) => new URL(f).hostname))].slice(0, 3).join(", ")}`));
    }

    const source = `${html}`;
    for (const [re, id, sev, score, t, d] of QS_SOURCE_INDICATORS) {
        if (re.test(source)) {
            if (id === "ms-assets" && QS_BRANDS.microsoft.some((dm) => qsHostIn(pageHost, dm))) continue;
            const strong = id === "ms-assets" && passwordFields > 0;
            signals.push(qsSignal(id, strong ? "high" : sev, strong ? 35 : score, t, d));
        }
    }

    // Obfuscation
    const obf = [];
    for (const [re, label, min = 1] of QS_OBFUSCATION) {
        const n = (inlineJs.match(re) || []).length;
        if (n >= min) obf.push(`${label} (${n}x)`);
    }
    if (obf.length) {
        const heavy = obf.length >= 3 || obf.some((o) => o.startsWith("obfuscator.io"));
        signals.push(qsSignal("obfuscation", heavy ? "medium" : "low", heavy ? 15 : 5, "Obfuscated JavaScript",
            `Techniques found: ${obf.join(", ")}. Used to hide redirects and exfiltration logic from scanners.`));
    }

    // HTML smuggling: builds a file in the browser and drops it as a download
    if (/new\s+Blob\s*\(/.test(inlineJs) && /createObjectURL|msSaveOrOpenBlob/.test(inlineJs) && /\.download\s*=|download=/.test(source)) {
        signals.push(qsSignal("html-smuggling", "high", 30, "HTML smuggling",
            "The page assembles a file in the browser and offers it as a download, bypassing mail and proxy scanning. Common malware delivery technique."));
    } else if (/data:application\/(?:octet-stream|zip|x-zip|x-msdownload)[^"']{0,40};base64/i.test(source)) {
        signals.push(qsSignal("data-download", "high", 25, "Embedded file download (data: URI)",
            "A binary file is embedded directly in the page."));
    }

    if (bodyText.length < 200 && scripts.length > 0) {
        signals.push(qsSignal("js-built", "info", 0, "Content is built by JavaScript",
            "Almost no static text: the real page is assembled at runtime, so static analysis sees only part of it. Compare with a rendered urlscan.io scan."));
    }
    if (metaRefresh || jsRedirects.length) {
        signals.push(qsSignal("client-redirect", "low", 5, "Client-side redirect",
            `${metaRefresh ? "Meta refresh" : "JavaScript"} redirect to ${metaRefresh || jsRedirects[0]}. Client-side hops hide the destination from simple link checkers.`));
    }

    const refs = Object.entries(refDomains).map(([host, v]) => ({ host, count: v.count, kinds: [...v.kinds] }))
        .sort((a, b) => b.count - a.count);

    return {
        title, textLength: bodyText.length, textSample: bodyText.slice(0, 400), forms, passwordFields,
        hasCardFields, hasOtpFields, iframes: iframes.slice(0, 10), externalScripts: externalScripts.slice(0, 30),
        inlineScriptBytes: inlineJs.length, metaRefresh, jsRedirects, pageBrands: [...new Set(pageBrands)],
        foreignBrands, referencedDomains: refs.slice(0, 60), signals,
    };
}

// ---------------------------------------------------------------------------
// Stage 2b: live fetch with redirect capture
// ---------------------------------------------------------------------------

function qsPickHeaders(headers) {
    const want = ["server", "content-type", "content-length", "location", "content-disposition", "x-powered-by",
        "refresh", "strict-transport-security", "cf-ray", "x-served-by", "via"];
    const out = {};
    let setCookies = 0;
    for (const h of headers || []) {
        const n = h.name.toLowerCase();
        if (n === "set-cookie") setCookies++;
        else if (want.includes(n)) out[n] = (h.value || "").slice(0, 300);
    }
    if (setCookies) out["set-cookie (count)"] = String(setCookies);
    return out;
}

/**
 * Register webRequest listeners that follow one extension-initiated request
 * through all its redirects. Firefox keeps the same requestId across redirects.
 */
function qsCreateCapture(startUrl) {
    const extBase = browser.runtime.getURL("");
    const cap = { requestId: null, hops: [], current: null, startUrl, tlsPending: [] };
    const newHop = (url) => ({ url, status: null, ip: null, headers: {}, tls: null, kind: "http" });
    const mine = (d) => cap.requestId !== null && d.requestId === cap.requestId;

    const onBeforeRequest = (d) => {
        if (cap.requestId === null && d.tabId === -1 && d.url === startUrl &&
            ((d.originUrl || d.documentUrl || "").startsWith(extBase) || !d.originUrl)) {
            cap.requestId = d.requestId;
            cap.current = newHop(d.url);
            cap.hops.push(cap.current);
        }
    };
    const onBeforeSendHeaders = (d) => {
        if (!mine(d)) return {};
        // Strip anything identifying the user or the extension; look like a top-level navigation
        const drop = new Set(["cookie", "origin", "referer", "authorization"]);
        const headers = d.requestHeaders.filter((h) => !drop.has(h.name.toLowerCase()) && !h.name.toLowerCase().startsWith("sec-fetch-"));
        const set = (name, value) => {
            const i = headers.findIndex((h) => h.name.toLowerCase() === name.toLowerCase());
            if (i >= 0) headers[i].value = value;
            else headers.push({ name, value });
        };
        set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        set("Accept-Language", "nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7");
        set("Upgrade-Insecure-Requests", "1");
        set("Sec-Fetch-Dest", "document");
        set("Sec-Fetch-Mode", "navigate");
        set("Sec-Fetch-Site", "none");
        set("Sec-Fetch-User", "?1");
        return { requestHeaders: headers };
    };
    const onHeadersReceived = (d) => {
        if (!mine(d) || !cap.current) return {};
        const hop = cap.current;
        hop.status = d.statusCode;
        hop.ip = d.ip || hop.ip;
        hop.headers = qsPickHeaders(d.responseHeaders);
        if (d.url.startsWith("https:")) {
            const p = browser.webRequest.getSecurityInfo(d.requestId, {}).then((si) => {
                const c = si?.certificates?.[0];
                hop.tls = {
                    state: si?.state, protocol: si?.protocolVersion,
                    subject: c?.subject, issuer: c?.issuer,
                    validFrom: c?.validity?.start, validTo: c?.validity?.end,
                    ageDays: c?.validity?.start ? qsDaysSince(c.validity.start) : null,
                };
            }).catch(() => {});
            cap.tlsPending.push(p);
            return p.then(() => ({}));
        }
        return {};
    };
    const onBeforeRedirect = (d) => {
        if (!mine(d) || !cap.current) return;
        cap.current.status = d.statusCode;
        cap.current.ip = d.ip || cap.current.ip;
        cap.current.redirectTo = d.redirectUrl;
        cap.current = newHop(d.redirectUrl);
        cap.hops.push(cap.current);
    };
    const onCompleted = (d) => {
        if (!mine(d) || !cap.current) return;
        cap.current.status = d.statusCode;
        cap.current.ip = d.ip || cap.current.ip;
    };
    const onErrorOccurred = (d) => {
        if (!mine(d) || !cap.current) return;
        cap.current.error = d.error;
    };

    const filter = { urls: ["<all_urls>"] };
    const wr = browser.webRequest;
    wr.onBeforeRequest.addListener(onBeforeRequest, filter);
    wr.onBeforeSendHeaders.addListener(onBeforeSendHeaders, filter, ["blocking", "requestHeaders"]);
    wr.onHeadersReceived.addListener(onHeadersReceived, filter, ["blocking", "responseHeaders"]);
    wr.onBeforeRedirect.addListener(onBeforeRedirect, filter);
    wr.onCompleted.addListener(onCompleted, filter);
    wr.onErrorOccurred.addListener(onErrorOccurred, filter);

    cap.dispose = async () => {
        await Promise.allSettled(cap.tlsPending);
        wr.onBeforeRequest.removeListener(onBeforeRequest);
        wr.onBeforeSendHeaders.removeListener(onBeforeSendHeaders);
        wr.onHeadersReceived.removeListener(onHeadersReceived);
        wr.onBeforeRedirect.removeListener(onBeforeRedirect);
        wr.onCompleted.removeListener(onCompleted);
        wr.onErrorOccurred.removeListener(onErrorOccurred);
    };
    return cap;
}

async function qsReadLimited(resp, max) {
    if (!resp.body) {
        const buf = new Uint8Array(await resp.arrayBuffer());
        return { bytes: buf.slice(0, max), truncated: buf.length > max };
    }
    const reader = resp.body.getReader();
    const chunks = [];
    let total = 0;
    let truncated = false;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        total += value.length;
        if (total > max) {
            truncated = true;
            await reader.cancel().catch(() => {});
            break;
        }
    }
    const bytes = new Uint8Array(Math.min(total, max));
    let off = 0;
    for (const c of chunks) {
        const take = Math.min(c.length, bytes.length - off);
        bytes.set(c.subarray(0, take), off);
        off += take;
        if (off >= bytes.length) break;
    }
    return { bytes, truncated };
}

async function qsSha256(bytes) {
    const h = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** One fetch round: follows HTTP redirects, returns hops + final response info */
async function qsFetchRound(url) {
    const cap = qsCreateCapture(url);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), QS_CONFIG.FETCH_TIMEOUT_MS);
    const result = { hops: [], final: null, error: null, captureMode: "webRequest" };
    try {
        const resp = await fetch(url, {
            method: "GET", redirect: "follow", credentials: "omit", cache: "no-store",
            referrerPolicy: "no-referrer", signal: ctrl.signal,
        });
        const ct = resp.headers.get("content-type") || "";
        const cd = resp.headers.get("content-disposition") || "";
        const { bytes, truncated } = await qsReadLimited(resp, QS_CONFIG.MAX_BODY_BYTES);
        const charset = (ct.match(/charset=([\w-]+)/i) || [])[1] || "utf-8";
        const isHtml = /html|xml/i.test(ct) || (!ct && /^\s*</.test(new TextDecoder().decode(bytes.slice(0, 200))));
        const isText = isHtml || /^text\/|javascript|json/i.test(ct);
        let text = null;
        if (isText) {
            try {
                text = new TextDecoder(charset).decode(bytes);
            } catch {
                text = new TextDecoder("utf-8").decode(bytes);
            }
        }
        const filename = (cd.match(/filename\*?=(?:UTF-8'')?["']?([^"';]+)/i) || [])[1] || null;
        result.final = {
            url: resp.url, status: resp.status, contentType: ct, size: bytes.length, truncated,
            sha256: await qsSha256(bytes), isHtml, isText, filename: filename ? qsSafeDecode(filename) : null,
            attachment: /attachment/i.test(cd), refreshHeader: resp.headers.get("refresh"),
        };
        result.text = text;
        result.redirected = resp.redirected;
    } catch (e) {
        result.error = e.name === "AbortError" ? `Timed out after ${QS_CONFIG.FETCH_TIMEOUT_MS / 1000}s` : e.message;
    } finally {
        clearTimeout(timer);
        await cap.dispose();
    }
    result.hops = cap.hops;
    if (!cap.hops.length) {
        // webRequest did not see the request: fall back to what fetch() exposes
        result.captureMode = "fetch-only";
        result.hops = [{ url, status: result.redirected ? "3xx" : result.final?.status ?? null, kind: "http" }];
        if (result.redirected && result.final) {
            result.hops.push({ url: result.final.url, status: result.final.status, kind: "http" });
        }
    }
    if (result.error && result.hops.length) result.hops[result.hops.length - 1].error ||= result.error;
    return result;
}

function qsChainSignals(live, startApex) {
    const signals = [];
    const hops = live.hops;
    const hosts = hops.map((h) => {
        try {
            return new URL(h.url).hostname.toLowerCase();
        } catch {
            return "";
        }
    });
    const apexes = [...new Set(hosts.map(qsApex).filter(Boolean))];
    const finalUrl = live.final?.url || hops[hops.length - 1]?.url;
    const finalApex = finalUrl ? qsApex(new URL(finalUrl).hostname) : null;

    if (hops.length - 1 >= 3) {
        signals.push(qsSignal("many-hops", "low", 5, `${hops.length - 1} redirects before the final page`,
            "Chains of redirectors are used to separate the link in the mail from the actual payload."));
    }
    if (apexes.length >= 3) {
        signals.push(qsSignal("many-domains", "low", 5, `Redirect chain crosses ${apexes.length} domains`, apexes.join(" → ")));
    }
    for (let i = 1; i < hops.length; i++) {
        if (hops[i - 1].url.startsWith("https:") && hops[i].url.startsWith("http:")) {
            signals.push(qsSignal("downgrade", "medium", 10, "HTTPS → HTTP downgrade in the chain",
                `${hosts[i - 1]} sends the visitor back to unencrypted HTTP. Sloppy or deliberate, either way unusual for legitimate services.`));
            break;
        }
    }
    if (finalApex && startApex && finalApex !== startApex && QS_POPULAR_DOMAINS.has(finalApex) && !QS_POPULAR_DOMAINS.has(startApex)) {
        signals.push(qsSignal("cloaking", "high", 25, `Possible cloaking: ends on ${finalApex}`,
            `An unknown domain (${startApex}) forwarded this fetch to a well-known, harmless site. Phishing redirectors do this for visitors they consider scanners, wrong country or wrong device. The real target may only be shown to "real" victims.`));
    }
    hops.forEach((h, i) => {
        if (h.tls?.ageDays != null && h.tls.ageDays <= 7 && !QS_POPULAR_DOMAINS.has(qsApex(hosts[i]))) {
            signals.push(qsSignal(`fresh-cert-${hosts[i]}`, "low", 8, `TLS certificate for ${hosts[i]} is ${h.tls.ageDays} day(s) old`,
                "Fresh certificates fit newly set-up infrastructure. Weak signal: Let's Encrypt certificates renew often."));
        }
        if (h.tls && h.tls.state && h.tls.state !== "secure") {
            signals.push(qsSignal(`tls-${hosts[i]}`, "medium", 10, `TLS state "${h.tls.state}" on ${hosts[i]}`, "The certificate is not fully trusted."));
        }
        if (QS_SHORTENERS.has(hosts[i]) && i > 0) {
            signals.push(qsSignal(`shortener-${hosts[i]}`, "low", 5, `URL shortener in chain (${hosts[i]})`, "Hides the next hop."));
        }
        const plat = qsPlatformOf(hosts[i]);
        if (plat && i > 0) {
            signals.push(qsSignal(`platform-${hosts[i]}`, "low", 8, `Chain uses a free hosting platform (${plat})`, hosts[i]));
        }
        const b = i > 0 ? qsBrandInHost(hosts[i]) : null;
        if (b) {
            signals.push(qsSignal(`brand-hop-${hosts[i]}`, "high", 30, `Redirect target uses the brand "${b}"`, `${hosts[i]} is not a ${b} domain.`));
        }
    });
    const first = hops[0];
    if (first && typeof first.status === "number" && [401, 403, 404, 410, 451, 503].includes(first.status)) {
        signals.push(qsSignal("refused", "info", 0, `Server answered ${first.status} on the first request`,
            "Either the campaign was taken down, the link was one-time, or the server filters visitors by IP/country/browser."));
    }
    const f = live.final;
    if (f && (f.attachment || (!f.isText && f.size > 0))) {
        const name = f.filename || new URL(f.url).pathname.split("/").pop() || "(unnamed)";
        const dangerous = QS_DANGEROUS_EXT.test(name) || /x-msdownload|x-msdos|zip|x-iso|octet-stream|x-rar|x-7z/i.test(f.contentType);
        signals.push(qsSignal("download", dangerous ? "high" : "medium", dangerous ? 30 : 10,
            `Link delivers a file: ${name}`,
            `Content-Type ${f.contentType || "unknown"}, ${f.size} bytes${f.truncated ? " (truncated)" : ""}. SHA-256 ${f.sha256}. Look the hash up on VirusTotal; do not open the file.`));
    }
    if (live.captureMode === "fetch-only") {
        signals.push(qsSignal("capture-limited", "info", 0, "Intermediate redirect hops not visible",
            "Firefox did not expose this request to webRequest, so only the start and final URL are known."));
    }
    return signals;
}

// ---------------------------------------------------------------------------
// Verdict, block candidates, persistence
// ---------------------------------------------------------------------------

function qsComputeVerdict(report) {
    const all = [
        ...(report.url?.signals || []),
        ...(report.enrichSignals || []),
        ...(report.live?.chainSignals || []),
        ...(report.live?.pages || []).flatMap((p) => p.analysis?.signals || []),
    ];
    const byId = new Map();
    for (const s of all) {
        const prev = byId.get(s.id);
        if (!prev || s.score > prev.score) byId.set(s.id, s);
    }
    const signals = [...byId.values()].sort((a, b) => b.score - a.score);
    const score = Math.min(100, signals.reduce((sum, s) => sum + (s.score || 0), 0));
    let level = "clean";
    let label = "No strong signals";
    if (score >= 60) {
        level = "high";
        label = "Malicious indicators";
    } else if (score >= 30) {
        level = "medium";
        label = "Suspicious";
    } else if (score >= 10) {
        level = "low";
        label = "Some risk signals";
    }
    return { signals, score, level, label };
}

function qsBlockCandidates(report) {
    const cands = new Map();
    const add = (host, reason, checked) => {
        if (!host || qsIsIp(host)) return;
        const plat = qsPlatformOf(host);
        // On shared platforms block the exact host, never the platform itself
        const domain = plat ? host : qsApex(host);
        if (QS_POPULAR_DOMAINS.has(domain)) return;
        if (Object.values(QS_BRANDS).some((list) => list && list.includes(domain))) return;
        const prev = cands.get(domain);
        if (prev) {
            if (!prev.reasons.includes(reason)) prev.reasons.push(reason);
            prev.checked = prev.checked || checked;
        } else {
            cands.set(domain, { domain, reasons: [reason], checked });
        }
    };
    const risky = report.verdict && report.verdict.score >= 10;
    add(report.url?.host, "link in the message", risky);
    for (const h of report.live?.hops || []) {
        try {
            add(new URL(h.url).hostname, "redirect chain", risky);
        } catch {
            /* ignore */
        }
    }
    for (const p of report.live?.pages || []) {
        for (const f of p.analysis?.forms || []) {
            try {
                const fh = new URL(f.action).hostname;
                if (qsApex(fh) !== qsApex(new URL(p.url).hostname)) add(fh, "form destination", true);
            } catch {
                /* ignore */
            }
        }
    }
    return [...cands.values()];
}

async function qsSave(report) {
    report.verdict = qsComputeVerdict(report);
    report.blockCandidates = qsBlockCandidates(report);
    report.updatedAt = new Date().toISOString();
    await browser.storage.local.set({ [QS_CONFIG.REPORT_PREFIX + report.id]: report });
}

async function qsLoad(id) {
    const key = QS_CONFIG.REPORT_PREFIX + id;
    const r = await browser.storage.local.get(key);
    return r[key] || null;
}

async function qsAddToIndex(report) {
    const { [QS_CONFIG.INDEX_KEY]: index = [] } = await browser.storage.local.get(QS_CONFIG.INDEX_KEY);
    index.unshift({ id: report.id, target: report.target, createdAt: report.createdAt });
    const removed = index.splice(QS_CONFIG.MAX_REPORTS);
    await browser.storage.local.set({ [QS_CONFIG.INDEX_KEY]: index });
    if (removed.length) {
        await browser.storage.local.remove(removed.flatMap((r) => [QS_CONFIG.REPORT_PREFIX + r.id, `ck_${r.id}`]));
    }
}

/** Block suggestions for a set of links (used by the scan queue page) */
function qsBlockCandidatesForLinks(links) {
    const merged = new Map();
    for (const l of links || []) {
        let host;
        try {
            host = new URL(l.url).hostname.toLowerCase();
        } catch {
            continue;
        }
        const fake = { url: { host }, verdict: { score: l.flagged ? 50 : 0 }, live: null };
        for (const c of qsBlockCandidates(fake)) {
            const prev = merged.get(c.domain);
            const reasons = l.flagged ? ["flagged by urlscan.io"] : ["in the scan queue"];
            if (prev) {
                prev.checked = prev.checked || c.checked;
                reasons.forEach((r) => prev.reasons.includes(r) || prev.reasons.push(r));
            } else {
                merged.set(c.domain, { domain: c.domain, reasons, checked: c.checked });
            }
        }
    }
    return [...merged.values()].sort((a, b) => Number(b.checked) - Number(a.checked) || a.domain.localeCompare(b.domain));
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/** Create a report, open it, and run the offline stage */
async function qsStart(input, options = {}) {
    let normalized;
    try {
        normalized = qsNormalizeInput(input);
    } catch {
        notifyError("Quick Scan", `Not a valid URL or domain: ${String(input).slice(0, 80)}`);
        return null;
    }
    const unwrap = qsUnwrapUrl(normalized);
    const report = {
        id: `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`,
        createdAt: new Date().toISOString(), input: String(input).slice(0, 4000),
        target: unwrap.url, unwrapSteps: unwrap.steps, status: "offline-running",
        url: null, hosts: {}, enrichSignals: [], live: null,
    };
    try {
        report.url = qsAnalyzeUrl(report.target);
    } catch (e) {
        report.status = "error";
        report.error = e.message;
    }
    await qsSave(report);
    await qsAddToIndex(report);
    // The page opens at once so the user sees something happening; tools to run are passed as parameters
    const extra = new URLSearchParams();
    if (options.run) extra.set("run", options.run);
    if (options.focus) extra.set("focus", options.focus);
    const qsParams = extra.toString();
    await browser.tabs.create({
        url: browser.runtime.getURL(`report.html?id=${report.id}${qsParams ? `&${qsParams}` : ""}`),
        active: true,
    });

    if (report.url) {
        const hosts = [report.url.host, ...report.url.embeddedUrls.map((u) => {
            try {
                return new URL(u).hostname;
            } catch {
                return null;
            }
        })].filter(Boolean).slice(0, 4);
        const results = await Promise.all([...new Set(hosts)].map((h) => qsEnrichHost(h)));
        results.forEach((r) => {
            report.hosts[r.host] = r;
        });
        report.enrichSignals = qsEnrichmentSignals(report.hosts, report.url.host);
        report.status = "offline-done";
        await qsSave(report);
    }
    return report.id;
}

const qsRunning = new Set();

/** Live stage: fetch from the user's connection, follow server + client redirects */
async function qsRunLive(id, options = {}) {
    if (qsRunning.has(id)) return { started: false, reason: "already running" };
    const granted = await browser.permissions.contains(QS_CONFIG.LIVE_PERMISSIONS);
    if (!granted || !browser.webRequest) return { started: false, reason: "permission" };
    const report = await qsLoad(id);
    if (!report || !report.url) return { started: false, reason: "not found" };
    qsRunning.add(id);

    const { qsFollowClient = true } = await browser.storage.sync.get("qsFollowClient");
    const follow = options.followClient ?? qsFollowClient;

    report.status = "live-running";
    report.live = { startedAt: new Date().toISOString(), hops: [], pages: [], chainSignals: [], captureMode: "webRequest" };
    await qsSave(report);

    try {
        let next = report.target;
        let kind = "start";
        for (let round = 0; round <= QS_CONFIG.MAX_CLIENT_HOPS && next; round++) {
            const r = await qsFetchRound(next);
            if (r.hops[0]) r.hops[0].kind = kind;
            report.live.hops.push(...r.hops);
            if (r.captureMode === "fetch-only") report.live.captureMode = "fetch-only";
            report.live.final = r.final;
            report.live.error = r.error;
            next = null;
            if (r.final && r.text && r.final.isHtml) {
                const analysis = qsAnalyzeHtml(r.text, r.final.url);
                report.live.pages.push({ url: r.final.url, status: r.final.status, analysis });
                const visited = new Set(report.live.hops.map((h) => h.url));
                const refresh = r.final.refreshHeader?.match(/url\s*=\s*['"]?([^'";]+)/i)?.[1];
                const candidates = [
                    [analysis.metaRefresh, "meta-refresh"],
                    [refresh ? qsResolve(refresh, r.final.url) : null, "refresh-header"],
                    [analysis.jsRedirects[0], "javascript"],
                ];
                const hit = candidates.find(([u]) => u && /^https?:/i.test(u) && !visited.has(u));
                if (follow && hit) {
                    [next, kind] = hit;
                }
            }
            report.live.chainSignals = qsChainSignals(report.live, report.url.apex);
            await qsSave(report);
        }

        // Enrich every host seen in the chain (and form destinations)
        const chainHosts = new Set();
        report.live.hops.forEach((h) => {
            try {
                chainHosts.add(new URL(h.url).hostname.toLowerCase());
            } catch {
                /* ignore */
            }
        });
        report.live.pages.forEach((p) => p.analysis.forms.forEach((f) => {
            try {
                chainHosts.add(new URL(f.action).hostname.toLowerCase());
            } catch {
                /* ignore */
            }
        }));
        const todo = [...chainHosts].filter((h) => !report.hosts[h]).slice(0, QS_CONFIG.MAX_ENRICH_HOSTS);
        const results = await Promise.all(todo.map((h) => qsEnrichHost(h)));
        results.forEach((r) => {
            report.hosts[r.host] = r;
        });
        report.enrichSignals = qsEnrichmentSignals(report.hosts, report.url.host);
        report.live.finishedAt = new Date().toISOString();
        report.status = "done";
    } catch (e) {
        console.error("Quick Scan live error:", e);
        report.status = "error";
        report.error = e.message;
    } finally {
        qsRunning.delete(id);
        await qsSave(report);
    }
    return { started: true };
}

// ---------------------------------------------------------------------------
// Messaging (report page <-> background)
// ---------------------------------------------------------------------------

if (typeof browser !== "undefined" && browser.runtime?.onMessage) {
    browser.runtime.onMessage.addListener((msg) => {
        if (!msg || typeof msg.action !== "string" || !msg.action.startsWith("qs")) return undefined;
        switch (msg.action) {
            case "qsRunLive":
                // Fire and forget; the page follows progress via storage.onChanged
                qsRunLive(msg.id, msg.options || {});
                return Promise.resolve({ ok: true });
            case "qsRescanOffline":
                return qsStart(msg.url, { run: msg.run, focus: msg.focus }).then((id) => ({ ok: !!id, id }));
            case "qsBlockCandidatesFor":
                return Promise.resolve({ candidates: qsBlockCandidatesForLinks(msg.links) });
            case "qsUrlscan":
                sendToUrlscan(msg.url);
                return Promise.resolve({ ok: true });
            case "qsVirusTotal":
                sendToVirusTotal(msg.url);
                return Promise.resolve({ ok: true });
            case "qsNextDnsProfiles":
                return Promise.resolve({ profiles: (typeof nextDnsProfiles !== "undefined" ? nextDnsProfiles : []).map((p) => ({ id: p.id, name: p.name || p.id })) });
            case "qsNextDnsBlock":
                return qsBlockDomains(msg.domains || [], msg.profileId);
            default:
                return undefined;
        }
    });
}

async function qsBlockDomains(domains, profileId) {
    const profiles = profileId === "all" ? nextDnsProfiles : nextDnsProfiles.filter((p) => p.id === profileId);
    const results = [];
    for (const domain of domains) {
        for (const p of profiles) {
            try {
                await addToNextDnsList(p.id, p.name || p.id, domain, "denylist", true);
                results.push({ domain, profile: p.name || p.id, ok: true });
            } catch (e) {
                results.push({ domain, profile: p.name || p.id, ok: false, error: e.message });
            }
        }
    }
    return { results };
}

// Node test hook (ignored in the browser)
if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        qsApex, qsNormalizeInput, qsUnwrapUrl, qsAnalyzeUrl, qsAnalyzeHtml, qsChainSignals,
        qsComputeVerdict, qsBlockCandidates, qsBrandInHost, qsTryBase64, qsFindJsRedirects,
        qsEnrichmentSignals,
    };
}
