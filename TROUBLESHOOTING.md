# Troubleshooting Guide

## Issue: NextDNS Not Appearing in Context Menu

### Symptoms
- Right-click a link
- See "Security Analysis" menu
- Only see "Scan with URLScan.io" and "⚙️ Configure Tools"
- NextDNS submenu is missing

### Solution Steps

#### Step 1: Check Browser Console
1. Open Firefox
2. Press `Ctrl+Shift+J` (Windows/Linux) or `Cmd+Opt+J` (Mac) to open Browser Console
3. Look for messages from the extension:
   - `Creating context menus...`
   - `Fetched X NextDNS profiles`
   - `✓ Created NextDNS menus for X profiles`

#### Step 2: Verify NextDNS API Key
1. Click the extension icon in toolbar
2. Scroll to "NextDNS Configuration" section
3. Check if API key field is filled
4. **Important**: Check for extra spaces - the field should auto-trim them now
5. Click "Save All Settings"
6. Look for green box showing "✓ Connected Profiles:"

#### Step 3: Check API Key Validity
1. Copy your NextDNS API key
2. Test it manually:
   ```bash
   curl -H "X-Api-Key: YOUR_API_KEY" https://api.nextdns.io/profiles
   ```
3. Should return JSON with your profiles
4. If it returns 401/403, your API key is invalid

#### Step 4: Reload Extension
1. Go to `about:debugging#/runtime/this-firefox`
2. Find your extension
3. Click "Reload" button
4. Check Browser Console for initialization messages

#### Step 5: Test Menu Creation
1. After saving NextDNS API key, wait 1-2 seconds
2. Right-click any link on a webpage
3. Check if NextDNS appears now
4. If not, check Browser Console for errors

### Common Issues

#### Issue: "No NextDNS profiles found"
**Cause**: API key is invalid or you have no profiles created

**Solution**:
1. Visit https://my.nextdns.io/
2. Check if you have any profiles
3. If not, create at least one profile
4. Get a fresh API key from https://my.nextdns.io/account
5. Paste it in the extension (whitespace will be auto-trimmed)
6. Save settings

#### Issue: Profiles show in settings but not in menu
**Cause**: Menu hasn't refreshed after saving

**Solution**:
1. Reload the extension at `about:debugging`
2. Or wait 1-2 seconds and try again
3. Check Browser Console for "Settings changed, recreating menus..."

#### Issue: Whitespace in API key
**Cause**: Copied API key from browser with trailing/leading spaces

**Solution**: 
- This is now fixed! The extension automatically trims whitespace
- When you save, the input field will update to show the trimmed value
- No need to manually remove spaces anymore

#### Issue: Context menu not updating after settings change
**Cause**: Storage listener might not have triggered

**Solution**:
1. Close all Firefox windows
2. Restart Firefox
3. Or reload extension at `about:debugging`

## Testing Checklist

Use this checklist to verify everything works:

### Initial Setup
- [ ] Install/load extension in Firefox
- [ ] Click toolbar icon - settings page opens
- [ ] See both URLScan.io and NextDNS sections
- [ ] NextDNS profiles section is hidden (no API key yet)

### URLScan.io Configuration
- [ ] Paste URLScan.io API key (with/without spaces)
- [ ] Save - success message appears
- [ ] Right-click any link
- [ ] See "Security Analysis" → "Scan with URLScan.io"

### NextDNS Configuration
- [ ] Paste NextDNS API key (test with extra spaces!)
- [ ] Click Save
- [ ] Green box appears showing "✓ Connected Profiles:"
- [ ] See your profile names listed
- [ ] Check Browser Console - should see "Fetched X NextDNS profiles"

### Context Menu - Basic
- [ ] Right-click any link
- [ ] See "Security Analysis" as parent menu
- [ ] Hover over it - submenu appears
- [ ] See "Scan with URLScan.io"
- [ ] See "NextDNS"
- [ ] See "⚙️ Configure Tools"

### Context Menu - NextDNS Submenu
- [ ] Right-click any link
- [ ] Security Analysis → NextDNS
- [ ] See "🚫 Add to Blocklist"
- [ ] See "✓ Add to Allowlist"
- [ ] Hover over blocklist - see your profiles
- [ ] Hover over allowlist - see your profiles

### Functional Testing - URLScan
- [ ] Right-click any link
- [ ] Security Analysis → Scan with URLScan.io
- [ ] Notification appears: "Scan submitted successfully!"
- [ ] After 10-15 seconds, new tab opens with results

### Functional Testing - NextDNS Blocklist
- [ ] Right-click any link (e.g., to example.com)
- [ ] Security Analysis → NextDNS → Add to Blocklist → [Your Profile]
- [ ] Notification appears: "Added 'example.com' to blocklist..."
- [ ] Visit https://my.nextdns.io/
- [ ] Go to your profile → Denylist
- [ ] See "example.com" in the list

### Functional Testing - NextDNS Allowlist
- [ ] Right-click any link
- [ ] Security Analysis → NextDNS → Add to Allowlist → [Your Profile]
- [ ] Notification appears: "Added 'X' to allowlist..."
- [ ] Visit https://my.nextdns.io/
- [ ] Go to your profile → Allowlist
- [ ] See the domain in the list

### Error Handling
- [ ] Try saving with invalid URLScan.io API key (too short)
- [ ] Error message appears
- [ ] Try with invalid NextDNS API key
- [ ] Notification says "NextDNS Configuration Missing" or API error
- [ ] Configure Tools option always works (opens settings)

## Debug Commands

### Check Extension Storage
Open Browser Console and run:
```javascript
browser.storage.sync.get().then(console.log)
```

Should show:
```javascript
{
  urlscanApiKey: "your-key",
  urlscanVisibility: "unlisted",
  urlscanTags: "firefox, extension",
  nextdnsApiKey: "your-nextdns-key"
}
```

### Manually Trigger Menu Rebuild
```javascript
browser.runtime.sendMessage({action: 'rebuildMenus'})
```

### Check Context Menus
Unfortunately, Firefox doesn't provide a way to list context menus via console.
You must right-click to see them.

## Getting Help

If you're still having issues:

1. **Check Browser Console** for error messages
2. **Check Extension Console** at `about:debugging`
3. **Verify API keys** work via curl commands
4. **Check NextDNS dashboard** to confirm you have profiles

### Report an Issue

When reporting issues, include:
- Firefox version
- Extension version (1.2.0)
- Browser Console output
- Steps to reproduce
- Screenshot of context menu
- Screenshot of settings page

Email: info@paulrutten.nl

## Known Limitations

- **Firefox 109+ Required**: Manifest V3 features
- **API Rate Limits**: Respect service rate limits
- **Profile Limit**: No hard limit, but too many profiles may make menu unwieldy
- **Domain Only**: NextDNS adds domains, not full URLs with paths
- **No Removal**: Currently can't remove from lists via extension (coming soon!)

## Advanced Troubleshooting

### Issue: Extension seems to hang
1. Open `about:debugging`
2. Click "Inspect" next to the extension
3. Check console for errors
4. Look for failed API requests

### Issue: Menus appear but actions don't work
1. Check Browser Console when clicking menu items
2. Look for "Scanning URL:" or "Adding X to blocklist"
3. If missing, event listener may have failed
4. Reload extension

### Issue: Settings don't persist
1. Check if Firefox Sync is working
2. Try using local storage:
   - Requires code modification
   - Change `browser.storage.sync` to `browser.storage.local`
3. Check Firefox storage quota isn't exceeded

## Performance Notes

- **Menu Creation**: Takes 100-500ms depending on profile count
- **Profile Fetching**: 200-1000ms depending on network
- **URLScan Submission**: ~15 seconds for full scan
- **NextDNS Addition**: Instant (<500ms)

## Security Notes

- **API Keys in Memory**: Briefly held during operations
- **No Logging**: API keys never logged to console
- **Local Storage**: Keys encrypted by Firefox
- **HTTPS Only**: All API calls use HTTPS
- **No Analytics**: Extension doesn't track usage

---

Last Updated: v1.2.0
