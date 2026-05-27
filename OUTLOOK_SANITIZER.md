# Outlook Safe Links Sanitizer

## Overview

Microsoft Outlook wraps URLs in "Safe Links" protection, making it difficult to see and manage the actual destination. This extension automatically detects and extracts the real URL from these protection wrappers.

## What Are Outlook Safe Links?

Outlook Safe Links protect users by wrapping all URLs in emails through Microsoft's scanning service:

**Wrapped Format:**
```
https://emea01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fmeqq.offersweep.com%2F...&data=...&sdata=...&reserved=0
```

**Actual URL (hidden inside):**
```
http://meqq.offersweep.com/...
```

**Domain we want:**
```
offersweep.com
```

## Supported Formats

The extension automatically detects and unwraps:

### Regional Variants
- ✅ `https://emea01.safelinks.protection.outlook.com/...` (Europe/Middle East/Africa)
- ✅ `https://nam12.safelinks.protection.outlook.com/...` (North America)
- ✅ `https://apac01.safelinks.protection.outlook.com/...` (Asia-Pacific)
- ✅ `https://eur02.safelinks.protection.outlook.com/...` (Europe)
- ✅ Any pattern: `[region][number].safelinks.protection.outlook.com`

### Legacy Format
- ✅ `https://safelinks.protection.outlook.com/...` (without region)

## How It Works

### Automatic Detection
1. Extension detects `safelinks.protection.outlook.com` in URL
2. Extracts the `url` parameter from query string
3. URL-decodes the parameter (converts `%3A` to `:`, etc.)
4. Extracts domain from the actual URL
5. Uses that domain for NextDNS or URLScan.io

### Example Flow

**Input (Outlook Safe Link):**
```
https://emea01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fmalware-site.com%2Fphishing&data=...
```

**Console Output:**
```
Outlook Safe Link detected. Original: https://emea01.safelinks.protection.outlook.com/?url=http%3A%2F%2F...
Extracted actual URL: http://malware-site.com/phishing
Adding malware-site.com to blocklist
```

**Result:**
- ✅ Domain extracted: `malware-site.com`
- ✅ Added to NextDNS blocklist
- ❌ NOT: `safelinks.protection.outlook.com`

## Use Cases

### Use Case 1: Phishing Email

**Scenario:** Receive suspicious email with link

1. Email contains Outlook Safe Link
2. Right-click the link
3. Security Analysis → Scan with URLScan.io
4. URLScan scans the ACTUAL malicious URL (not the wrapper)
5. If malicious → Add to NextDNS blocklist
6. Extension extracts real domain automatically

### Use Case 2: Quick Block

**Scenario:** Know link is malicious, want to block immediately

1. Right-click Outlook Safe Link in email
2. Security Analysis → NextDNS → Add to Blocklist
3. Extension extracts real domain
4. Blocks `malware-site.com`, NOT `outlook.com`

### Use Case 3: Allowlist Legitimate Links

**Scenario:** Corporate email with legitimate partner link

1. Link wrapped by Outlook for safety
2. Need to allowlist the actual domain
3. Right-click → NextDNS → Add to Allowlist
4. Real domain allowlisted (e.g., `partner-company.com`)
5. Won't accidentally allowlist Microsoft's infrastructure

### Use Case 4: Security Investigation

**Scenario:** Analyzing phishing campaign

1. Forward suspicious emails to security team
2. Each contains multiple wrapped links
3. For each link:
   - Right-click → Scan with URLScan.io
   - Review actual destination
   - Add malicious domains to blocklist
4. Build blocklist of campaign domains

## Technical Details

### URL Parameter Extraction

Outlook Safe Links use standard URL parameters:
```
https://region.safelinks.protection.outlook.com/?url=<encoded>&data=<metadata>&sdata=<signature>&reserved=0
```

**Parameters:**
- `url` - The actual destination (URL-encoded)
- `data` - Tracking/metadata (ignored)
- `sdata` - Signature for verification (ignored)
- `reserved` - Reserved field (ignored)

The extension:
1. Parses the URL using `URL` API
2. Gets `url` parameter using `searchParams.get('url')`
3. Decodes using `decodeURIComponent()`
4. Recursively extracts domain from result

### URL Encoding Examples

| Encoded | Decoded |
|---------|---------|
| `%3A` | `:` |
| `%2F` | `/` |
| `%3F` | `?` |
| `%3D` | `=` |
| `%26` | `&` |

### Recursive Extraction

The function is recursive, meaning it can handle:
- Outlook Safe Links containing URLScan.io links
- Double-wrapped URLs
- Multiple protection layers

Example:
```
Outlook Safe Link → URLScan domain page → Actual domain
https://outlook.com/?url=urlscan.io/domain/malware.com
→ urlscan.io/domain/malware.com
→ malware.com ✅
```

## Testing

### Test URLs

Use these to test the feature:

**Test 1: Simple HTTP URL**
```
https://emea01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fexample.com%2F&data=05&sdata=xxx&reserved=0
```
Expected: `example.com`

**Test 2: HTTPS with Path**
```
https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Ftest-site.org%2Fpath%2Fto%2Fpage&data=05&sdata=xxx&reserved=0
```
Expected: `test-site.org`

**Test 3: With Query Parameters**
```
https://apac01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fdomain.com%2F%3Fid%3D123%26ref%3Demail&data=05&sdata=xxx&reserved=0
```
Expected: `domain.com`

### Manual Testing Steps

1. **Create Test Email** (optional):
   - Send yourself an email with a link
   - Outlook will wrap it in Safe Links
   
2. **Or Use Example URL**:
   - Copy one of the test URLs above
   - Paste in a test HTML page

3. **Test Extraction**:
   - Right-click the Safe Link
   - Open Browser Console (`Ctrl+Shift+J`)
   - Look for: "Outlook Safe Link detected"
   - Look for: "Extracted actual URL: ..."
   - Verify correct domain extracted

4. **Test with NextDNS**:
   - Right-click Safe Link
   - Security Analysis → NextDNS → Add to Blocklist
   - Check notification shows REAL domain
   - Verify in NextDNS dashboard

## Console Debugging

Enable detailed logging:

**Successful Extraction:**
```
Context menu clicked: {
  menuItemId: "nextdns-blocklist-abc123",
  linkUrl: "https://emea01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fmalware.com%2F...",
  target: "https://emea01.safelinks.protection.outlook.com/?url=..."
}
Outlook Safe Link detected. Original: https://emea01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fmalware.com%2F...
Extracted actual URL: http://malware.com/path
Adding malware.com to blocklist for profile abc123
NextDNS: Successfully added malware.com to denylist
```

**Failed Extraction (falls back to original):**
```
Failed to extract from Outlook Safe Link: [error details]
```

## Edge Cases

### Handled Correctly
- ✅ Multiple URL parameters in actual URL
- ✅ Anchor fragments (`#section`)
- ✅ Already decoded URLs
- ✅ Missing `url` parameter (uses whole URL)
- ✅ Nested encoding
- ✅ International domains

### Known Limitations
- ❌ Requires `url` parameter (standard Outlook format)
- ❌ Corrupted or truncated Safe Links
- ❌ Custom corporate Safe Link wrappers (non-Microsoft)

If extraction fails, extension uses the original URL (safe fallback).

## Privacy & Security

### What Gets Sent to NextDNS/URLScan.io
- ✅ The ACTUAL destination domain
- ❌ NOT the Outlook Safe Link wrapper
- ❌ NOT Microsoft tracking data
- ❌ NOT email metadata

### Microsoft Tracking
- The `data` and `sdata` parameters contain Microsoft tracking info
- Extension ignores these completely
- Only the actual URL is used

## Integration with Other Features

### Works With:
- ✅ URLScan.io scanning
- ✅ NextDNS blocklist/allowlist
- ✅ Selected text extraction
- ✅ URLScan.io domain extraction
- ✅ All profile selection

### Example Workflow:
1. Receive phishing email (links wrapped by Outlook)
2. Right-click link → Scan with URLScan.io
3. URLScan analyzes REAL destination
4. On results page, see malicious domains
5. Select domain → Add to NextDNS blocklist
6. Both URLScan and Safe Link extraction work together!

## Comparison: Before vs After

### Before This Feature

**Wrapped URL:**
```
https://emea01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fmalware.com%2F...
```

**What would happen:**
- ❌ Would try to block: `safelinks.protection.outlook.com`
- ❌ Would break Outlook email links
- ❌ Would NOT block actual malware site

### After This Feature

**Same Wrapped URL:**
```
https://emea01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fmalware.com%2F...
```

**What happens now:**
- ✅ Automatically detects Outlook wrapper
- ✅ Extracts: `http://malware.com/...`
- ✅ Blocks: `malware.com`
- ✅ Outlook links continue working
- ✅ Actual threat blocked

## FAQ

**Q: Does this bypass Outlook's protection?**
A: No. Outlook Safe Links still scan the URL first. This just helps you manage the ACTUAL destination after Outlook checks it.

**Q: Will this break my Outlook links?**
A: No. The extension only extracts domains for NextDNS/URLScan.io. It doesn't modify or block the Outlook wrapper.

**Q: What if the wrapped URL is also malicious?**
A: The extension extracts and uses the REAL destination, which is what matters for blocking.

**Q: Can I use this with other email services?**
A: The Outlook Safe Links sanitizer is specific to Microsoft Outlook/365. Other services may need separate handlers.

**Q: Does this work with Office 365?**
A: Yes! Office 365 uses the same Safe Links format.

## Future Enhancements

Planned features:
- [ ] Google Safe Browsing wrapper detection
- [ ] ProofPoint URL Defense sanitizer
- [ ] Cisco Email Security wrapper
- [ ] Mimecast URL rewrite handling
- [ ] Custom wrapper pattern support

## Related Features

See also:
- [Advanced Features Guide](ADVANCED_FEATURES.md) - Selected text support
- [NextDNS Integration](NEXTDNS_INTEGRATION.md) - Blocklist management
- [README](README.md) - General documentation

---

**Version**: 1.2.0  
**Status**: Active ✅  
**Supported Regions**: Global (all Outlook Safe Links variants)
