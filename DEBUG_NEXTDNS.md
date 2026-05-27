# Quick Debug Steps - NextDNS Not Appearing

## Step 1: Test Your API Key

1. **Open Extension Settings**
   - Click the extension icon in Firefox toolbar
   - Scroll to "NextDNS Configuration"

2. **Enter Your API Key**
   - Paste your NextDNS API key
   - Click the new **"🔍 Test Connection"** button (don't save yet!)

3. **Check the Result**
   - ✅ Success: "Connection successful! Found X profile(s): [names]"
   - ❌ Failed: Check the error message

### Common Test Results:

**"Connection successful! Found 2 profiles: Home, Office"**
- ✅ Your API key works!
- ✅ You have profiles
- → Click "Save All Settings" and wait 2 seconds
- → Right-click any link to check menu

**"Connection failed (401): Unauthorized"**
- ❌ API key is invalid or expired
- → Get a new API key from https://my.nextdns.io/account
- → Make sure you're copying the ENTIRE key

**"Connection failed (403): Forbidden"**
- ❌ API key doesn't have permission
- → Generate a new API key with full permissions

**"Connection successful but no profiles found"**
- ⚠️ API key works but you have no profiles
- → Go to https://my.nextdns.io/ and create a profile first
- → Then test again

**"Network error: Failed to fetch"**
- ❌ Can't reach NextDNS API
- → Check your internet connection
- → Check if nextdns.io is accessible
- → Try disabling VPN/proxy temporarily

## Step 2: Check Browser Console

1. **Open Browser Console**
   - Press `Ctrl+Shift+J` (Windows/Linux)
   - Or `Cmd+Opt+J` (Mac)

2. **Look for These Messages After Clicking "Test Connection":**
   ```
   Testing NextDNS API connection...
   NextDNS profiles: [Array with your profiles]
   ```

3. **Look for These Messages After Clicking "Save All Settings":**
   ```
   Settings changed, recreating menus...
   Creating context menus...
   Fetching NextDNS profiles with API key length: XX
   NextDNS API response status: 200
   NextDNS profiles fetched successfully: 2 profiles
   Profile names: Home, Office
   ✓ Created NextDNS menus for 2 profiles
   ```

## Step 3: Check What's in Storage

In Browser Console, run:
```javascript
browser.storage.sync.get('nextdnsApiKey').then(console.log)
```

Should output:
```javascript
{nextdnsApiKey: "your-api-key-here"}
```

If it shows `{}` or `{nextdnsApiKey: ""}`, the key wasn't saved!

## Step 4: Manual Menu Rebuild

If profiles were fetched but menu still doesn't show, manually trigger rebuild:

1. Go to `about:debugging#/runtime/this-firefox`
2. Find your extension
3. Click **"Reload"**
4. Check Browser Console for initialization logs
5. Right-click any link to test

## Step 5: Full Reset

If nothing works:

1. **Clear All Settings**
   ```javascript
   // In Browser Console:
   browser.storage.sync.clear()
   ```

2. **Reload Extension**
   - `about:debugging` → Reload

3. **Start Fresh**
   - Click extension icon
   - Enter URLScan.io API key (optional)
   - Enter NextDNS API key
   - Click "Test Connection" first
   - If test succeeds, click "Save All Settings"
   - Wait 2 seconds
   - Right-click any link

## Expected Console Output (Success)

When everything works, you should see this sequence:

```
[On Extension Load]
Security Analysis extension loaded successfully
Creating context menus...
Fetching NextDNS profiles with API key length: 32
NextDNS API response status: 200
NextDNS profiles fetched successfully: 2 profiles
Profile names: Home, Office
✓ Created NextDNS menus for 2 profiles
✓ Context menus created successfully

[When You Save Settings]
Settings saved: {visibility: "unlisted", tags: "firefox, extension", hasNextDns: true}
Settings changed, recreating menus...
Creating context menus...
Fetching NextDNS profiles with API key length: 32
NextDNS API response status: 200
NextDNS profiles fetched successfully: 2 profiles
Profile names: Home, Office
✓ Created NextDNS menus for 2 profiles
✓ Context menus created successfully
```

## If You See Errors

### "NextDNS API key not configured in storage"
- The API key wasn't saved
- Try saving again
- Check storage with: `browser.storage.sync.get('nextdnsApiKey')`

### "NextDNS API response status: 401"
- Invalid API key
- Get new key from https://my.nextdns.io/account

### "NextDNS API response status: 429"
- Rate limited
- Wait 1 minute and try again

### "Failed to fetch NextDNS profiles"
- Network issue or API problem
- Test manually: 
  ```bash
  curl -H "X-Api-Key: YOUR_KEY" https://api.nextdns.io/profiles
  ```

## Quick Checklist

Before reporting an issue, verify:
- [ ] Used "Test Connection" button - shows success
- [ ] API key is saved (check in storage)
- [ ] Clicked "Save All Settings" after test
- [ ] Waited 2 seconds after saving
- [ ] Reloaded extension at about:debugging
- [ ] Checked Browser Console for errors
- [ ] Right-clicked on an actual link (not empty space)
- [ ] Firefox version is 109+ (check at about:support)

## Still Not Working?

Send to info@paulrutten.nl:
1. Screenshot of "Test Connection" result
2. Browser Console output (copy/paste text)
3. Result of: `browser.storage.sync.get().then(console.log)`
4. Firefox version
5. Screenshot of context menu

---

**Pro Tip**: Always use "Test Connection" BEFORE saving! This helps identify API key issues immediately.
