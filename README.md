# Security Tools Firefox Extension

A professional Firefox extension that integrates multiple security analysis tools directly into your browser's context menu. Analyze links with URLScan.io, manage DNS filtering with NextDNS, and more.

## Features

- 🔒 **URLScan.io Integration**: Comprehensive website security scanning
- 🛡️ **NextDNS Integration**: DNS-level blocklist/allowlist management  
- 📱 **Multi-Profile Support**: Manage multiple NextDNS profiles
- ⚙️ **Easy Configuration**: Simple settings page with real-time validation
- 🎨 **Professional UI**: Modern, clean interface
- 🔐 **Secure Storage**: API keys stored locally in Firefox's secure storage
- 📊 **Extensible**: More security tools coming soon

## Current Integrations

### 1. URLScan.io
- Detailed website security analysis
- Screenshot and HTTP request inspection
- Malware and phishing detection
- Automatic result opening

### 2. NextDNS  
- Add domains to blocklists (DNS-level blocking)
- Add domains to allowlists (ensure access)
- Dynamic profile selection
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
- Get your API key from [profile page](https://urlscan.io/user/profile/)

**NextDNS (Optional):**
- Register at [NextDNS](https://my.nextdns.io/signup)
- Get your API key from [account settings](https://my.nextdns.io/account)

### 2. Configure Extension

- Click the extension icon in your Firefox toolbar
- Enter your URLScan.io API key
- (Optional) Enter your NextDNS API key
- Choose scan visibility (Public/Unlisted/Private)
- Customize tags (default: `firefox, extension`)
- Click "Save All Settings"

### 3. Start Using

**URLScan.io:**
- Right-click any link → Security Analysis → Scan with URLScan.io
- Wait for scan to complete (results open automatically)

**NextDNS:**
- Right-click any link → Security Analysis → NextDNS
- Choose "Add to Blocklist" or "Add to Allowlist"
- Select which profile to add the domain to

## Technical Details

### Manifest Version
- **Version**: 3 (Manifest V3)
- **Minimum Firefox**: 109.0+

### Permissions
- `contextMenus`: For right-click menu integration
- `activeTab`: To access the current tab's context
- `tabs`: To open scan results in new tabs
- `storage`: To securely store user settings
- `notifications`: To display scan status updates
- `https://urlscan.io/*`: To communicate with urlscan.io API

### File Structure
```
/app/
├── manifest.json          # Extension manifest (Manifest V3)
├── background.js          # Background service worker
├── options.html           # Settings page
├── options.js             # Settings logic
├── icons/                 # Extension icons
│   ├── urlscan_16.png
│   ├── urlscan_32.png
│   └── urlscan_256.png
└── README.md             # This file
```

## API Integration

This extension integrates with the [urlscan.io API v1](https://urlscan.io/docs/api/):

- **Scan Submission**: `POST https://urlscan.io/api/v1/scan/`
- **Result Polling**: `GET https://urlscan.io/api/v1/result/{uuid}/`

### Scan Flow
1. User right-clicks a link and selects "Scan with urlscan.io"
2. Extension submits the URL to urlscan.io API
3. Initial 10-second delay (scans typically take 10-15 seconds)
4. Polls every 2 seconds for up to 40 seconds
5. Opens results page automatically when ready

## Privacy & Security

- **Local Storage Only**: API keys are stored exclusively in Firefox's secure local storage
- **No Third-Party Sharing**: Your API key is never transmitted to any service except urlscan.io
- **User Control**: You control scan visibility (public/unlisted/private)
- **Open Source**: All code is available for inspection

## Development

### Code Quality
- ✅ ESLint validated
- ✅ Modern ES6+ JavaScript
- ✅ Comprehensive error handling
- ✅ JSDoc documentation
- ✅ Input validation

### Testing
To test the extension:
1. Load it temporarily in Firefox (`about:debugging`)
2. Configure your API key in the options page
3. Right-click any link and test the scanning functionality
4. Verify notifications appear correctly
5. Confirm results page opens automatically

## Changelog

### Version 1.2.0 (Current)
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

**Developer**: Paul Rutten (info@paulrutten.nl)

**Powered by**: 
- [urlscan.io](https://urlscan.io/) - Website security scanner
- [urlscan.io API](https://urlscan.io/docs/api/) - Public API
- [NextDNS](https://nextdns.io/) - DNS-level security and privacy
- [NextDNS API](https://nextdns.github.io/api/) - Public API

## License

This extension is provided as-is for use with urlscan.io's services. Please refer to urlscan.io's terms of service for API usage guidelines.

## Support

For issues or questions:
- Email: info@paulrutten.nl
- Check [urlscan.io documentation](https://urlscan.io/docs/api/)

## Mozilla Add-ons Submission Checklist

- ✅ Manifest V3 compliant
- ✅ Clear privacy policy (API keys stored locally)
- ✅ All permissions justified and documented
- ✅ No obfuscated code
- ✅ Comprehensive error handling
- ✅ User-friendly interface
- ✅ Professional design
- ✅ Proper versioning
- ✅ Complete documentation
- ✅ Tested on Firefox 109+
