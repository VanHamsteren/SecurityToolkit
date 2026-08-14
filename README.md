# Security Toolkit Firefox Extension

A professional Firefox extension that integrates multiple security analysis tools directly into your browser's context menu. Analyze suspicious links with URLScan.io, VirusTotal, and AbuseIPDB, check domain age via RDAP, pivot to external threat intelligence sites, and block malicious domains with NextDNS — all from a right-click.

Built for triaging spam, scam, and phishing links (e.g. from the junk folder in Outlook or Gmail on the web): analyze how an attack works, then block the domains behind it.

## Features

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

- **URLScan.io** → Scan Now, or Add to Scan Queue / Process Queue for batches
- **VirusTotal** → Scan Now
- **AbuseIPDB** → Check IP Reputation
- **NextDNS** → Add to Blocklist / Allowlist (per profile or all)
- **Domain Age (RDAP)** → registration date and age notification
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

## Changelog

### Version 1.4.1 (Current)
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
