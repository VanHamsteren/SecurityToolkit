# NextDNS Integration Guide

## Overview

This extension now integrates with NextDNS, allowing you to quickly add domains to your NextDNS blocklists and allowlists directly from the browser context menu.

## Features

### 🚫 Blocklist Management
- Right-click any link → Security Analysis → NextDNS → Add to Blocklist
- Select which profile to add the domain to
- Instantly blocks the domain at DNS level

### ✅ Allowlist Management
- Right-click any link → Security Analysis → NextDNS → Add to Allowlist
- Select which profile to add the domain to
- Ensures the domain is never blocked

### 🔄 Dynamic Profile Loading
- Automatically fetches your NextDNS profiles
- Shows profile names in context menu
- Supports unlimited profiles

## Setup Instructions

### 1. Get Your NextDNS API Key

1. Sign up for NextDNS: https://my.nextdns.io/signup
2. Log in to your account
3. Go to Account Settings: https://my.nextdns.io/account
4. Scroll to "API" section
5. Click "Create API Key"
6. Copy your API key

### 2. Configure the Extension

1. Click the extension icon in Firefox toolbar
2. Scroll to "NextDNS Configuration" section
3. Paste your API key
4. Click "Save All Settings"
5. Your profiles will appear below the API key field

### 3. Use the Integration

#### To Block a Domain:
1. Right-click any link on a webpage
2. Hover over "Security Analysis"
3. Hover over "NextDNS"
4. Hover over "🚫 Add to Blocklist"
5. Click on your desired profile name
6. You'll get a notification confirming the domain was added

#### To Allow a Domain:
1. Right-click any link on a webpage
2. Hover over "Security Analysis"
3. Hover over "NextDNS"
4. Hover over "✓ Add to Allowlist"
5. Click on your desired profile name
6. You'll get a notification confirming the domain was added

## How It Works

### Domain Extraction
The extension automatically extracts the domain from the full URL:
- `https://example.com/path/to/page` → `example.com`
- `https://subdomain.example.com` → `subdomain.example.com`

This domain is what gets added to your NextDNS lists.

### API Integration
The extension uses the NextDNS API v1:
- **Profiles**: `GET https://api.nextdns.io/profiles`
- **Add to Blocklist**: `PUT https://api.nextdns.io/profiles/{id}/denylist/{domain}`
- **Add to Allowlist**: `PUT https://api.nextdns.io/profiles/{id}/allowlist/{domain}`

### Profile Management
- Profiles are fetched when you save your API key
- Menus are dynamically created based on your profiles
- If you add/remove profiles in NextDNS, just resave your API key in the extension to refresh

## Context Menu Structure

```
Security Analysis
├── Scan with URLScan.io
├── NextDNS
│   ├── 🚫 Add to Blocklist
│   │   ├── Profile 1
│   │   ├── Profile 2
│   │   └── Profile 3...
│   └── ✓ Add to Allowlist
│       ├── Profile 1
│       ├── Profile 2
│       └── Profile 3...
├── ──────────────
└── ⚙️ Configure Tools
```

## Use Cases

### 1. Quick Ad Blocking
- Browse a website
- See an annoying ad from a specific domain
- Right-click → Add to blocklist
- Domain is now blocked on all your devices using that NextDNS profile

### 2. Phishing Protection
- Receive a suspicious email with a link
- Right-click the link → Add to blocklist
- Protect yourself and others on your network

### 3. Parental Controls
- See inappropriate content
- Right-click → Add to blocklist on your family profile
- Content is blocked across all family devices

### 4. Developer Testing
- Testing DNS filtering
- Quickly add/remove domains to test behavior
- Manage multiple profiles for different environments

## Troubleshooting

### Profiles Not Showing
- **Issue**: NextDNS profiles don't appear in the context menu
- **Solution**: 
  1. Check your API key is correct
  2. Resave your settings
  3. Check browser console for errors

### Domain Not Added
- **Issue**: Get an error notification when adding domain
- **Solution**:
  1. Verify API key is valid
  2. Check you have permissions for the profile
  3. Ensure you're not hitting rate limits

### Menus Not Updating
- **Issue**: Added a new NextDNS profile but it doesn't show
- **Solution**: Resave your NextDNS API key in extension settings

## Privacy & Security

- **API Key Storage**: Your NextDNS API key is stored locally in Firefox's secure storage
- **No Tracking**: We don't track what domains you block/allow
- **Direct API Calls**: All API calls go directly from your browser to NextDNS
- **No Middleman**: Your data never passes through our servers

## API Rate Limits

NextDNS API has reasonable rate limits:
- **Read Operations**: ~100 requests per minute
- **Write Operations**: ~30 requests per minute

The extension caches profile data to minimize API calls.

## Advanced Usage

### Multiple Profiles Strategy
- **Profile 1 (Personal)**: Your personal blocklist
- **Profile 2 (Family)**: Shared family protection
- **Profile 3 (Work)**: Work-specific filtering
- **Profile 4 (Testing)**: Development/testing

### Blocklist vs Allowlist
- **Blocklist**: Prevents DNS resolution for the domain (blocks access)
- **Allowlist**: Ensures domain is never blocked, even by other rules

## Future Enhancements

Planned features:
- [ ] View existing lists before adding
- [ ] Remove from lists
- [ ] Bulk import/export
- [ ] Search functionality
- [ ] List statistics
- [ ] Integration with NextDNS analytics

## API Documentation

For more details on the NextDNS API:
- Official Docs: https://nextdns.github.io/api/
- API Base URL: `https://api.nextdns.io`
- Authentication: `X-Api-Key` header

## Support

For issues or questions:
- Extension: info@paulrutten.nl
- NextDNS: https://help.nextdns.io/

## Related Resources

- [NextDNS Homepage](https://nextdns.io/)
- [NextDNS Setup Guide](https://help.nextdns.io/t/g9hdkjz/how-to-setup-nextdns)
- [NextDNS API Documentation](https://nextdns.github.io/api/)
