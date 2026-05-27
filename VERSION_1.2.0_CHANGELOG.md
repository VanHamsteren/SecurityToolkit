# Version 1.2.0 - NextDNS Integration & Security Menu

## 🎉 Major New Features

### 1. NextDNS Integration
- **Add to Blocklist**: Block domains at DNS level across all your devices
- **Add to Allowlist**: Ensure domains are never blocked
- **Dynamic Profile Support**: Automatically loads all your NextDNS profiles
- **Profile-based Management**: Select which profile to add domains to

### 2. Reorganized Context Menu
- **New "Security Analysis" Parent Menu**: Clean, organized structure
- **Submenu for NextDNS**: Easy access to blocklist/allowlist options
- **Profile-based Submenus**: Each profile appears as a menu item
- **Configure Tools Option**: Quick access to settings from context menu

### 3. Enhanced Options Page
- **NextDNS API Key Field**: Secure password-masked input
- **Live Profile Display**: See your connected profiles in real-time
- **Improved Layout**: Better organization with sections for each tool
- **Future Integrations Preview**: See what's coming next

## 🔧 Technical Improvements

### Context Menu System
- Dynamic menu creation based on configured integrations
- Nested menu structure (4 levels deep)
- Automatic menu refresh when settings change
- Unicode icons for better visual identification (🚫, ✓, ⚙️)

### NextDNS API Integration
- Profile fetching: `GET /profiles`
- Domain management: `PUT /profiles/{id}/denylist/{domain}`
- Domain allowlisting: `PUT /profiles/{id}/allowlist/{domain}`
- Proper error handling and notifications

### Domain Extraction
- Automatic domain extraction from full URLs
- Handles subdomains correctly
- Validates URL format before processing

### Storage Management
- NextDNS API key stored securely
- Profile data cached in memory
- Settings sync across devices (Firefox Sync)

## 🎨 UI/UX Updates

### Options Page
- New NextDNS configuration section
- Real-time profile fetching and display
- Green success box showing connected profiles
- Toggle visibility for NextDNS API key
- "Future Security Tools" section showing roadmap

### Notifications
- Tool-specific notification prefixes
- Clear success/error messages
- Domain and profile names in messages
- Proper formatting and Unicode symbols

## 📝 Menu Structure

```
Right-click on any link → 

Security Analysis
├── Scan with URLScan.io
├── NextDNS
│   ├── 🚫 Add to Blocklist
│   │   ├── Profile 1
│   │   ├── Profile 2
│   │   └── Profile N...
│   └── ✓ Add to Allowlist
│       ├── Profile 1
│       ├── Profile 2
│       └── Profile N...
├── ─────────────────────
└── ⚙️ Configure Tools
```

## 🔒 Security & Privacy

- NextDNS API key stored locally in Firefox secure storage
- No third-party data sharing
- Direct API calls from browser to NextDNS
- API keys never logged or exposed
- Proper HTTPS for all API communications

## 📚 New Documentation

### Added Files
- `NEXTDNS_INTEGRATION.md` - Complete NextDNS setup and usage guide
- `VERSION_1.2.0_CHANGELOG.md` - This file

### Updated Files
- `README.md` - Added NextDNS feature documentation
- `manifest.json` - Version bump to 1.2.0
- `background.js` - Complete rewrite with NextDNS support
- `options.html` - Added NextDNS configuration section
- `options.js` - Added profile fetching logic

## 🚀 Future Integrations (Roadmap)

The new menu structure supports easy addition of:

### Planned for v1.3.0
- **VirusTotal**: Multi-engine malware scanning (70+ antivirus engines)
- **Google Safe Browsing**: Phishing and malware detection

### Planned for v1.4.0
- **AbuseIPDB**: IP reputation checking
- **Have I Been Pwned**: Breach checking

### Under Consideration
- **Shodan**: IP/domain reconnaissance
- **PhishTank**: Phishing verification
- **AlienVault OTX**: Threat intelligence
- **Hybrid Analysis**: Malware analysis sandbox

## 🐛 Bug Fixes

- Fixed context menu structure for better organization
- Improved error handling for API failures
- Better validation for API key formats
- Fixed menu creation race conditions

## ⚡ Performance

- Profile data cached to reduce API calls
- Debounced profile fetching (1 second delay)
- Efficient menu creation (batch operations)
- Minimal memory footprint

## 🔄 Migration from 1.1.0

No migration needed! Your existing URLScan.io settings are preserved:
1. Update to v1.2.0
2. (Optional) Add NextDNS API key
3. All URLScan.io functionality continues working
4. New NextDNS features available immediately

## 📦 Installation

Same as before:
1. Load extension in Firefox
2. Click toolbar icon to configure
3. Add URLScan.io API key (existing)
4. Add NextDNS API key (new!)
5. Save settings
6. Right-click any link to use features

## 🧪 Testing Checklist

For developers and testers:
- [ ] URLScan.io still works (backward compatibility)
- [ ] Context menu shows "Security Analysis" parent
- [ ] NextDNS submenu appears when API key configured
- [ ] Profiles load correctly (check with 1, 2, 5+ profiles)
- [ ] Domain extraction works for various URL formats
- [ ] Blocklist addition works
- [ ] Allowlist addition works
- [ ] Notifications appear correctly
- [ ] Error handling works (invalid API key)
- [ ] Settings persist across browser restart
- [ ] Menu updates when settings change

## 📊 Statistics

- **Lines of Code Added**: ~400
- **New API Integrations**: 1 (NextDNS)
- **New Menu Items**: Dynamic (2 + 2×profile_count)
- **New Settings Fields**: 1 (NextDNS API key)
- **Documentation Pages**: 2 new

## 🙏 Acknowledgments

- **URLScan.io**: For their excellent security scanning API
- **NextDNS**: For their powerful DNS filtering platform
- **Mozilla**: For the excellent WebExtensions API
- **Users**: For feedback and feature requests

## 📞 Support

- **Extension Issues**: info@paulrutten.nl
- **URLScan.io Help**: https://urlscan.io/docs/
- **NextDNS Help**: https://help.nextdns.io/

## 🔗 Resources

- [Extension Homepage](https://addons.mozilla.org/)
- [URLScan.io](https://urlscan.io/)
- [NextDNS](https://nextdns.io/)
- [NextDNS API Docs](https://nextdns.github.io/api/)
- [Source Code](https://github.com/your-repo)

---

**Version**: 1.2.0  
**Release Date**: 2025  
**Compatibility**: Firefox 109+  
**Manifest**: V3
