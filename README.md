# Security Toolkit Firefox Extension

A professional Firefox extension that integrates multiple security analysis tools directly into your browser's context menu. Analyze suspicious links with URLScan.io, VirusTotal, and AbuseIPDB, check domain age via RDAP, pivot to external threat intelligence sites, and block malicious domains with NextDNS — all from a right-click.

Built for triaging spam, scam, and phishing links (e.g. from the junk folder in Outlook or Gmail on the web): analyze how an attack works, then block the domains behind it.

## Features

- 🧭 **One results page per link** (new in 1.6): right-click > Security Analysis > *Analyse link (all tools)* opens a single page with a four-step flow (Analyse, Check reputation, Look deeper, Decide and block). urlscan.io, VirusTotal, AbuseIPDB and domain age each get a card that fills in live, and one overall assessment combines them
- ⏳ **Clear progress feedback**: buttons show a spinner and lock while an API call runs, a progress bar runs along the top of the page, and the toolbar button shows a badge while a job starts, so repeated clicking is no longer needed
- 🎨 **House style**: the whole extension follows the paulrutten.nl style book (Rice Terrace palette, Plus Jakarta Sans and Merriweather, light and dark mode, logo usage). Fonts are bundled, nothing is loaded from third parties
- ⚡ **Quick Scan (built-in)**: The extension's own link analysis with a full report page: redirect chain, cloaking detection, phishing-kit indicators, infrastructure lookups and one-click NextDNS blocking. No account or API key needed
- 🔒 **URLScan.io Integration**: Comprehensive website security scanning, with a batch scan queue
- 🧪 **VirusTotal Integration**: URL analysis with 70+ antivirus engines and blocklist services
- 🛰️ **AbuseIPDB Integration**: IP reputation checks with automatic domain→IP resolution
- 📅 **Domain Age (RDAP)**: Registration date lookup — flags recently registered domains, a common phishing signal
- 🔎 **Pivot Lookups**: One-click search on Talos, IBM X-Force, ScamAdviser, urlscan.io, VirusTotal, and Google Safe Browsing
- 🛡️ **NextDNS Integration**: DNS-level blocklist/allowlist management
- 📱 **Multi-Profile Support**: Manage multiple NextDNS profiles, including "All Profiles" at once
- 🔕 **Notification Levels**: All / Errors only / None — no toast spam during large batch scans
- ⚙️ **Easy Configuration**: Settings page with per-service Test Connection buttons and quota display
- 🔐 **Secure Storage**: API keys stored locally in Firefox's secure storage

## Current Integrations

### ⚡ Quick Scan (built-in, no API key)
Runs inside the extension and opens a report page. Two stages:

**1. Offline analysis** (never contacts the target server)
- Unwraps Microsoft Safe Links, Proofpoint URL Defense, Barracuda, Google and Facebook redirect wrappers; re-fangs defanged input (`hxxp`, `[.]`)
- Decodes base64 path/query segments, detects recipient tracking IDs and e-mail addresses in the link (personalised links)
- Flags IP-address hosts, punycode, `user@host` tricks, high-abuse TLDs, brand names in look-alike domains, free hosting platforms and URL shorteners
- DNS (A/CNAME/NS) via Google DNS-over-HTTPS, network/ASN via Team Cymru (over DNS), domain age and registrar via RDAP

**2. Live fetch** (on request, or automatic if enabled)
- Fetches the URL from your own connection, so it sees what a real (Dutch) victim sees, which helps against scanner cloaking
- Cookies, `Origin`, `Referer` and `Authorization` are stripped; the request is shaped like a normal top-level navigation
- Records every redirect hop (status, server IP, TLS issuer and certificate age via Firefox's `getSecurityInfo`), then follows meta-refresh / `Refresh` header / literal JavaScript redirects (max 5)
- Reads the response as **text only**: it is parsed with an inert `DOMParser`, nothing is rendered and no script runs. Max 2 MB, 15 s timeout
- Page indicators: password and card fields, MFA-code fields, brand impersonation (login form claiming Microsoft/ING/PostNL/... on a foreign domain), cloned Microsoft sign-in assets (AiTM kits), forms posting to other domains, exfiltration to Telegram bots / Discord webhooks / form services, visitor IP-geolocation lookups, CAPTCHA gates, anti-analysis tricks, obfuscated JavaScript, HTML smuggling and file downloads (with SHA-256 for a VirusTotal lookup)
- Chain indicators: cloaking (unknown domain forwarding to a well-known harmless site), HTTPS→HTTP downgrades, number of hops and domains, refused first requests

**Report page**
- Heuristic score (0-100) with every signal explained, redirect chain table, infrastructure table, link dissection and per-page analysis
- Block candidates (only the attacker's domains, never the decoy or brand domains) → NextDNS denylist in one click
- Second opinion: send the unwrapped URL to urlscan.io / VirusTotal, or pivot to urlscan history, VT and Talos
- Export as Markdown (defanged URLs, ready for a ticket or abuse report) or JSON; the last 25 reports are kept under *Recent Quick Scans* in the toolbar popup

### 1. URLScan.io
- Detailed website security analysis with screenshots and HTTP request inspection
- Malware and phishing detection; results open automatically
- **Scan Queue**: add URLs throughout the day, process them all at once (rate-limited)

### 2. VirusTotal
- Submits URLs for analysis by 70+ engines
- Polls until the analysis completes, then opens the results page

### 3. AbuseIPDB
- Checks IP reputation based on community abuse reports (last 90 days)
- Automatically resolves domains to their IP via DNS-over-HTTPS
- Shows abuse confidence score, report count, ISP and country; opens the details page for reporting

### 4. Domain Age (RDAP)
- Queries the official registry RDAP service (no API key needed)
- Warns when a domain was registered less than 6 months ago

### 5. Pivot Lookups (no API needed)
- Talos Intelligence, IBM X-Force Exchange, ScamAdviser, urlscan.io search, VirusTotal domain page, Google Safe Browsing transparency report

### 6. NextDNS
- Add domains to blocklists (DNS-level blocking) or allowlists
- Per-profile or all profiles at once
- Instant network-wide protection

## Installation

### For Users
1. Download the latest release
2. Open Firefox and navigate to `about:addons`
3. Click the gear icon and select "Install Add-on From File"
4. Select the downloaded `.xpi` file

### For Developers
1. Clone this repository
2. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
3. Click "Load Temporary Add-on"
4. Select any file in the extension directory

## Setup

### 1. Get API Keys

**URLScan.io:**
- Register at [urlscan.io](https://urlscan.io/user/signup)
- Get your API key from the [profile page](https://urlscan.io/user/profile/)

**VirusTotal (Optional):**
- Register at [virustotal.com](https://www.virustotal.com/gui/join-us)
- Get your API key from [your API key page](https://www.virustotal.com/gui/my-apikey)
- Free tier: 4 requests/minute, 500/day

**AbuseIPDB (Optional):**
- Register at [abuseipdb.com](https://www.abuseipdb.com/register)
- Get your API key from [account API settings](https://www.abuseipdb.com/account/api)
- Free tier: 1,000 checks/day

**NextDNS (Optional):**
- Register at [NextDNS](https://my.nextdns.io/signup)
- Get your API key from [account settings](https://my.nextdns.io/account)

Domain Age (RDAP) and Pivot Lookups require no account or API key.

### 2. Configure Extension

- Click the extension icon → Settings, or right-click → Security Analysis → Configure Tools
- Enter your API keys and click each **Test Connection** button — this also grants the required host permission (Firefox will show a one-time permission prompt for VirusTotal and AbuseIPDB)
- Choose scan visibility for URLScan.io (Public/Unlisted/Private) and customize tags
- Set your preferred notification level (default: Errors only)
- Click "Save All Settings"

### 3. Start Using

Right-click any link (or selected text) → **Security Analysis**:

- **Add to queue (analyse later) / Analyse the queue** → collect links, then analyse them in one go with the tools you choose
- **URLScan.io** → Scan Now, or *Add to urlscan.io queue* / *Scan the urlscan.io queue*: a separate queue whose links only go to urlscan.io
- **VirusTotal** → Scan Now
- **AbuseIPDB** → Check IP Reputation
- **NextDNS** → Add to Blocklist / Allowlist (per profile or all)
- **Domain Age (RDAP)** → registration date and age notification
- **⚡ Quick Scan** → own analysis in a report page (offline first, live fetch on request)
- **Lookup on…** → open the domain on an external analysis site

## Technical Details

### Manifest Version
- **Version**: 3 (Manifest V3)
- **Minimum Firefox**: 142.0+

### Permissions
- `contextMenus`: Right-click menu integration
- `activeTab` / `tabs`: Open results in new tabs
- `storage`: Securely store user settings
- `notifications`: Scan status and lookup results
- `https://urlscan.io/*`: URLScan.io API
- `https://api.nextdns.io/*`: NextDNS API
- `https://www.virustotal.com/*`: VirusTotal API (granted on first use)
- `https://api.abuseipdb.com/*`: AbuseIPDB API (granted on first use)
- Optional, for the Quick Scan live fetch only (requested on first use or via Settings): `<all_urls>` to fetch the link, `webRequest` + `webRequestBlocking` to record redirect hops, read TLS info and strip cookies/Origin from that one request. Listeners are attached only while a live fetch runs

Note: Firefox MV3 treats host permissions as opt-in. The Test Connection buttons in settings request the permission with a one-time prompt. RDAP (rdap.org) and DNS-over-HTTPS (dns.google) need no host permission because those services support cross-origin requests.

## API Integration

- **URLScan.io** ([API v1](https://urlscan.io/docs/api/)): `POST /api/v1/scan/`, polling `GET /api/v1/result/{uuid}/`, quota check via `/user/quotas/`
- **VirusTotal** ([API v3](https://docs.virustotal.com/reference/overview)): `POST /api/v3/urls`, polling `GET /api/v3/analyses/{id}`
- **AbuseIPDB** ([API v2](https://docs.abuseipdb.com/)): `GET /api/v2/check`
- **NextDNS** ([API](https://nextdns.github.io/api/)): profile list and denylist/allowlist management
- **RDAP** ([rdap.org](https://rdap.org/)): registry bootstrap for domain registration data
- **Google DNS-over-HTTPS** ([dns.google](https://developers.google.com/speed/public-dns/docs/doh)): domain→IP resolution for AbuseIPDB checks

### URLScan Flow
1. Right-click a link → Scan with URLScan.io (or queue it)
2. Extension submits the URL to the urlscan.io API
3. Initial 10-second delay, then polls every 2 seconds (up to 40 seconds)
4. Opens the results page automatically when ready
5. Queue processing waits 2.5 seconds between scans to respect rate limits

## Privacy & Security

- **Local Storage Only**: API keys are stored exclusively in Firefox's secure local storage
- **No Third-Party Sharing**: API keys are only ever sent to their own service (urlscan.io key to urlscan.io, etc.)
- **User Control**: You control URLScan visibility (public/unlisted/private) and notification level
- **Domain lookups**: RDAP and DNS-over-HTTPS lookups only transmit the domain being checked
- **Quick Scan**: reports are stored only in local extension storage (last 25). The live fetch runs only on your request (or when you enable automatic mode), sends no cookies, and is never shared with third parties; ASN lookups send the server IP to Team Cymru via Google DNS
- **Open Source**: All code is available for inspection

## Development

### Code Quality
- ✅ ESLint validated
- ✅ Modern ES6+ JavaScript
- ✅ Comprehensive error handling
- ✅ JSDoc documentation
- ✅ Input validation

### Testing
1. Load the extension temporarily in Firefox (`about:debugging`)
2. Configure API keys in the options page and use the Test Connection buttons
3. Right-click links and test each integration
4. Verify notifications respect the configured notification level
5. Confirm results pages open automatically
6. Quick Scan: right-click a junk-mail link → ⚡ Quick Scan, check the offline report, then **Fetch live** and verify the redirect chain and signals

## Changelog

### Version 1.7.11 (Current)
- 🌳 The block step of both queues now also lists every domain from the urlscan.io domain chain of each link, as the single-link analysis already did. Domains from a flagged link are ticked; popular sites and shared platforms are still left out

### Version 1.7.10
- 🔁 New option on the queue page: *Also analyse links whose domain is already on my NextDNS denylist*. Ticking it puts the skipped links back in line; they keep an *Already blocked in NextDNS* label next to their verdict
- 🐛 The queue page no longer shows a stray "null" between its sections
- ↔️ The link column in the queue table is wider, so links wrap less

### Version 1.7.9
- ♻️ Restores everything from the published 1.7.2 to 1.7.6 releases that 1.7.7 dropped by accident (1.7.7 was built from older source):
  - the toolkit's own queue directly under *Security Analysis*: *Add to queue (analyse later)* and *Analyse the queue*, for links and selected text
  - the queue page runs Quick Scan plus the tools you tick (urlscan.io, AbuseIPDB, VirusTotal), in batches, with earlier runs kept apart
  - the version badge in the toolbar popup, read from the manifest
  - domains already on a NextDNS denylist are marked in the block step
  - a warning when urlscan.io was redirected to a well-known harmless site (cloaking)
  - 100 recent analyses instead of 25
- 🌳 Keeps the urlscan.io domain chain tree from 1.7.0
- 📋 The queue entry stays in the menu when nothing is waiting (*Open the queue*), and its count follows the queue page
- 🆕 A second, separate queue in the *URLScan.io* submenu for links that should only go to urlscan.io (also reachable from the popup)
- 🔤 *URLScan.io, Scan Now* also works on selected text

### Version 1.7.8
- 📋 The scan queue is always reachable from the right-click menu: *Security Analysis, URLScan.io* shows *Process Queue* when links are waiting, otherwise *Open Scan Queue*

### Version 1.7.7
- 🌳 urlscan.io card now shows the **full domain chain**: every domain the page redirected through or loaded, as a tree under the host that led to it
- 🛡️ Step 4 offers those chain domains for NextDNS blocking (popular sites and shared platforms are still never suggested; ticked when urlscan.io flags the scan)

### Version 1.6.1
- 🐛 Results page no longer says "NextDNS is not set up" when it is: the profile list is now loaded on demand
- 🐛 Long URLs in the recent analyses list wrap inside their card
- 🐛 Test results on the settings page appear under the button you pressed
- 🐛 Popup no longer shows a scan that is not running; interrupted links go back to waiting

### Version 1.6.0
- 🧭 New unified results page: one page per scan with a four-step stepper, a card per tool (urlscan.io, VirusTotal, AbuseIPDB, domain age, more lookups), one combined assessment and a single block panel
- 📋 Scan queue now has its own page with progress, a verdict per link and block suggestions for flagged domains; *Process queue* in the popup and menu opens it
- ⏳ Busy states on every action that waits for an API (spinner, locked button, top progress bar, screen-reader announcement, repeat clicks ignored), plus a toolbar badge and a guard against double menu clicks
- 🎨 Restyled results, settings and popup to the paulrutten.nl style book (logo, colours, fonts, dark mode, 44 px targets, focus rings, reduced-motion support)
- 🧹 Settings page: sectioned layout, queue management moved to the queue page, no `innerHTML`
### Version 1.5.0
- ⚡ New built-in **Quick Scan**: offline link dissection plus DNS/ASN/RDAP enrichment, optional live fetch with full redirect chain capture, static phishing-kit analysis, cloaking detection and a report page with NextDNS blocking and Markdown/JSON export
- 🔐 New optional permissions (`<all_urls>`, `webRequest`, `webRequestBlocking`), only requested when the live fetch is used
- 🧭 Toolbar popup: *Recent Quick Scans*

### Version 1.4.2
- 🦊 New permanent add-on ID (firefox@paulrutten.nl) ahead of AMO submission
- 🔒 Removed remote Google Fonts stylesheet from options page (AMO policy; falls back to system fonts)

### Version 1.4.1
- 📝 Updated contact email to securitytoolkit@paulrutten.nl
- ☕ Added Buy Me a Coffee support link

### Version 1.4.0
- ✨ Added AbuseIPDB integration (IP reputation check with automatic domain→IP resolution, opens details page for reporting)
- ✨ Added Domain Age check via RDAP — flags recently registered domains (a common phishing signal)
- ✨ Added "Lookup on…" pivot submenu: Talos, IBM X-Force, ScamAdviser, urlscan.io search, VirusTotal domain, Google Safe Browsing
- ✨ Test Connection buttons for URLScan.io and VirusTotal (with quota display)
- 🔐 Runtime host-permission requests for new integrations (Firefox MV3)

### Version 1.3.0
- ✨ Added VirusTotal integration (scan URLs, auto-open results)
- ✨ Added notification level setting (All / Errors only / None) — default "Errors only" to reduce toast spam during batch scanning
- 🎨 Added NextDNS and VirusTotal icons to the context menu
- 🐛 Fixed single-profile NextDNS blocklist menu doing nothing (broken condition)

### Version 1.2.0
- ✨ Added NextDNS integration
- ✨ Added blocklist/allowlist management
- ✨ Dynamic profile loading and selection
- ✨ Reorganized context menu with "Security Analysis" parent
- ✨ Added profile display in settings
- 🎨 Enhanced UI with NextDNS configuration
- 📝 Comprehensive documentation for NextDNS
- 🔄 Menu structure supports future integrations

### Version 1.1.0
- ✨ Upgraded to Manifest V3
- ✨ Added customizable tags feature (defaults: firefox, extension)
- 🐛 Fixed polling delay bug
- 🎨 Complete UI redesign with urlscan.io branding
- 🔐 Added API key show/hide toggle
- ✅ Added comprehensive input validation
- 📝 Improved error messages and user feedback
- 🏗️ Better code structure with JSDoc comments
- ♿ Added accessibility improvements

### Version 1.0.0
- Initial release
- Basic URL scanning functionality
- Context menu integration
- Settings page

## Credits

**Developer**: Paul Rutten (securitytoolkit@paulrutten.nl)

If you like my work and want to support it (or my rampaging coffee addiction), consider making a donation via [☕ Buy Me a Coffee](https://buymeacoffee.com/nyana).

**Powered by**:
- [urlscan.io](https://urlscan.io/) - Website security scanner
- [VirusTotal](https://www.virustotal.com/) - Multi-engine URL and file analysis
- [AbuseIPDB](https://www.abuseipdb.com/) - Community-driven IP abuse reports
- [NextDNS](https://nextdns.io/) - DNS-level security and privacy
- [RDAP](https://rdap.org/) - Registry data access protocol
- [Google Public DNS](https://dns.google/) - DNS-over-HTTPS resolution
- [Cisco Talos](https://talosintelligence.com/), [IBM X-Force](https://exchange.xforce.ibmcloud.com/), [ScamAdviser](https://www.scamadviser.com/), [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search) - Pivot lookup sources

## License

This extension is provided as-is for use with the integrated services. Please refer to each service's terms for API usage guidelines: [urlscan.io](https://urlscan.io/about/), [VirusTotal](https://www.virustotal.com/gui/terms-of-service), [AbuseIPDB](https://www.abuseipdb.com/legal), [NextDNS](https://nextdns.io/terms).

## Support

For issues or questions:
- Email: securitytoolkit@paulrutten.nl
- Support the project: [☕ Buy Me a Coffee](https://buymeacoffee.com/nyana)
- API documentation: [urlscan.io](https://urlscan.io/docs/api/) | [VirusTotal](https://docs.virustotal.com/reference/overview) | [AbuseIPDB](https://docs.abuseipdb.com/) | [NextDNS](https://nextdns.github.io/api/)
