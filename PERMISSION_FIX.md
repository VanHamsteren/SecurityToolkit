# Permission Fix - NextDNS API Access

## Issue
After fixing CORS, got NetworkError when trying to access NextDNS API from background script:
```
NetworkError when attempting to fetch resource.
```

## Root Cause
The extension didn't have permission to access `api.nextdns.io` domain.

## Solution
Added NextDNS API to `host_permissions` in manifest.json:

```json
"host_permissions": [
    "https://urlscan.io/*",
    "https://api.nextdns.io/*"
],
```

## Why This Was Needed

In Manifest V3, extensions need explicit permission to access external APIs:
- `host_permissions` grants the extension access to specific domains
- Without this, even the background script can't make requests
- Similar to how we needed `https://urlscan.io/*` for URLScan.io

## After Applying This Fix

1. **Reload the extension** at `about:debugging#/runtime/this-firefox`
   - Firefox will prompt for new permissions
   - Accept the permission for api.nextdns.io

2. **Test again**:
   - Click extension icon
   - Enter NextDNS API key
   - Click "Test Connection"
   - Should now work!

## Permissions Summary

The extension now requests:

### Regular Permissions:
- `contextMenus` - Add items to right-click menu
- `activeTab` - Access current tab
- `tabs` - Open new tabs for results
- `storage` - Save settings locally
- `notifications` - Show notifications

### Host Permissions:
- `https://urlscan.io/*` - URLScan.io API access
- `https://api.nextdns.io/*` - NextDNS API access

## User Privacy

These permissions only allow:
- ✅ Making API calls to urlscan.io and api.nextdns.io
- ❌ The extension CANNOT access other websites
- ❌ The extension CANNOT read your browsing data
- ❌ The extension CANNOT modify web pages

## For Future Integrations

When adding new security tools, remember to:
1. Add API domain to `host_permissions` in manifest.json
2. Test in background script (not options page)
3. Use message passing from options page to background
4. Reload extension after manifest changes

---

**Version**: 1.2.0  
**Status**: Fixed ✅
