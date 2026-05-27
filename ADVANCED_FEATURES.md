# Advanced Features Guide

## Selected Text Support

The extension now works with BOTH links and selected text, making it more powerful and flexible.

### How It Works

#### Method 1: Right-Click on Links (Original)
1. Right-click any hyperlink
2. Security Analysis → Choose your action
3. Extension uses the link URL

#### Method 2: Select Text and Right-Click (NEW!)
1. **Select** any domain or URL text on the page
2. Right-click the selection
3. Security Analysis → Choose your action
4. Extension uses the selected text

### Use Cases

#### 1. URLScan.io Results Pages

**Problem**: On URLScan results, links show as:
- Display: `websitefullofmalware.com`
- Actual URL: `https://urlscan.io/domain/websitefullofmalware.com`

**Solution 1 - Smart Extraction (Automatic)**:
- Right-click the link
- Extension automatically detects URLScan.io format
- Extracts `websitefullofmalware.com` from the URL
- Adds the correct domain to NextDNS

**Solution 2 - Select Text**:
- Select the domain text: `websitefullofmalware.com`
- Right-click the selection
- Security Analysis → NextDNS → Add to Blocklist
- Uses exactly what you selected

#### 2. Plain Text Domains

If you see a domain in plain text (not a link):
```
Check out example-malware.com for more info
```

1. **Select** `example-malware.com`
2. Right-click → Security Analysis → NextDNS → Add to Blocklist
3. Domain is added instantly

#### 3. Email or Chat Messages

Domains in emails or chat apps:
```
Received spam from bad-actor.com today
```

1. **Select** `bad-actor.com`
2. Right-click → NextDNS → Add to Blocklist
3. Block it across all devices

#### 4. Documentation or Reports

Security reports often list domains:
```
IOCs (Indicators of Compromise):
- malicious-site.com
- phishing-domain.net
- cryptominer.org
```

For each domain:
1. **Select** the domain
2. Right-click → Add to Blocklist
3. Repeat for all IOCs

### Smart Domain Extraction

The extension intelligently handles various formats:

| Input | Extracted Domain |
|-------|-----------------|
| `https://example.com/path` | `example.com` |
| `example.com` | `example.com` |
| `urlscan.io/domain/malware.com` | `malware.com` |
| `outlook.com/?url=http%3A%2F%2Fmalware.com` | `malware.com` ⭐ |
| `subdomain.example.com` | `subdomain.example.com` |
| `Check malware.com here` | `malware.com` |

**NEW: Outlook Safe Links Support**
- Automatically unwraps Microsoft Outlook protection links
- Extracts the real destination URL
- Works with all regional variants (EMEA, NAM, APAC, etc.)
- See [OUTLOOK_SANITIZER.md](OUTLOOK_SANITIZER.md) for details

### Which Method to Use?

**Use Right-Click on Link When:**
- ✅ Link is available
- ✅ URL format is standard
- ✅ URLScan.io result pages (auto-detects)

**Use Select Text When:**
- ✅ Domain is plain text (not a link)
- ✅ Display text differs from link URL
- ✅ You want precise control
- ✅ Working with lists of domains
- ✅ In emails or chat apps

### Examples

#### Example 1: URLScan.io Workflow

**Scenario**: Scanning suspicious email link
1. Receive email with link
2. Right-click → Security Analysis → Scan with URLScan.io
3. URLScan results open showing malicious domains
4. On results page, **select** a malicious domain
5. Right-click selection → NextDNS → Add to Blocklist
6. Domain blocked on all devices

#### Example 2: Security Report

**Scenario**: Reading threat intelligence report
```
New phishing campaign using:
- fake-bank.com
- secure-login-verify.net
- account-update.org
```

For each domain:
1. **Select** domain (e.g., `fake-bank.com`)
2. Right-click → NextDNS → Add to Blocklist → [Profile]
3. Continue with next domain

#### Example 3: Forum or Reddit Post

**Scenario**: Someone shares a malicious domain
```
Warning: Don't visit cryptoscam.io - it's a phishing site!
```

1. **Select** `cryptoscam.io`
2. Right-click → NextDNS → Add to Blocklist
3. Protected immediately

### Tips & Tricks

**Tip 1: Quick Selection**
- Double-click to select a word
- Triple-click to select a line
- Drag to select specific text

**Tip 2: Verify Before Adding**
- Check the domain is correct
- Watch for typos in selection
- Console shows extracted domain

**Tip 3: Batch Processing**
- Open security report
- Select and add each IOC
- Faster than manual entry

**Tip 4: URLScan Integration**
- Scan unknown link first
- Review results
- Add malicious domains to blocklist
- All in one workflow!

### Console Debugging

Enable Browser Console to see extraction:
```javascript
Context menu clicked: {
  menuItemId: "nextdns-blocklist-abc123",
  linkUrl: "https://urlscan.io/domain/malware.com",
  selectedText: null,
  target: "https://urlscan.io/domain/malware.com"
}
Extracted domain from URLScan: malware.com
Adding malware.com to blocklist for profile abc123
```

Or with selected text:
```javascript
Context menu clicked: {
  menuItemId: "nextdns-blocklist-abc123",
  linkUrl: null,
  selectedText: "malicious-domain.com",
  target: "malicious-domain.com"
}
Adding malicious-domain.com to blocklist for profile abc123
```

### Supported Formats

The extension can extract domains from:
- ✅ Full URLs with protocol
- ✅ URLs without protocol
- ✅ Plain domain names
- ✅ URLScan.io result URLs
- ✅ Domains in sentences
- ✅ Subdomains
- ✅ International domains

### Limitations

**Cannot Handle:**
- ❌ Multiple domains in one selection (picks first found)
- ❌ IP addresses (NextDNS doesn't support)
- ❌ URLs with authentication (user:pass@domain)
- ❌ Data URLs or blob URLs

**Workaround**: Select one domain at a time

### Future Enhancements

Coming soon:
- [ ] Bulk domain addition (select multiple)
- [ ] IP address support
- [ ] Custom extraction patterns
- [ ] History of added domains
- [ ] Undo last addition

---

**Pro Tip**: Combine URLScan.io scanning with NextDNS management for a complete security workflow!

1. Right-click suspicious link → Scan with URLScan.io
2. Review scan results
3. Select malicious domains → Add to NextDNS blocklist
4. Protected network-wide instantly

**Version**: 1.2.0
