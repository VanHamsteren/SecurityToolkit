# Security Tools Extension - Feature Comparison & Roadmap

## Current Features (v1.2.0)

| Feature | URLScan.io | NextDNS | VirusTotal* | AbuseIPDB* | Safe Browsing* |
|---------|------------|---------|-------------|------------|----------------|
| **Status** | ✅ Active | ✅ Active | 🔜 Planned | 🔜 Planned | 🔜 Planned |
| **Function** | Website security scan | DNS filtering | Multi-AV scan | IP reputation | Phishing check |
| **Input** | Full URL | Domain only | URL/File | IP address | URL |
| **Output** | New tab with results | Notification | Scan report | Risk score | Risk level |
| **Cost** | Free tier available | Free tier available | Free tier | Free tier | Free API |
| **API Key Required** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |

*Coming in future versions

## Integration Details

### 1. URLScan.io (✅ Available)

**What it does:**
- Scans websites for security threats
- Takes screenshots of pages
- Analyzes HTTP requests
- Checks for malware, phishing, and suspicious behavior

**How to use:**
1. Right-click any link
2. Security Analysis → Scan with URLScan.io
3. Wait 10-15 seconds
4. Results open automatically in new tab

**API Key:** https://urlscan.io/user/profile/

**Best for:**
- Detailed website analysis
- Visual inspection of suspicious sites
- HTTP request analysis
- Finding hidden redirects

---

### 2. NextDNS (✅ Available)

**What it does:**
- Blocks domains at DNS level
- Allows trusted domains
- Works across all your devices
- Real-time DNS filtering

**How to use:**

**Blocklist:**
1. Right-click any link
2. Security Analysis → NextDNS → 🚫 Add to Blocklist
3. Select profile
4. Domain blocked instantly

**Allowlist:**
1. Right-click any link
2. Security Analysis → NextDNS → ✓ Add to Allowlist
3. Select profile
4. Domain whitelisted instantly

**API Key:** https://my.nextdns.io/account

**Best for:**
- Ad blocking
- Parental controls
- Privacy protection
- Network-wide filtering

---

### 3. VirusTotal (🔜 Coming Soon)

**What it will do:**
- Scan URLs with 70+ antivirus engines
- Check file hashes
- View historical scan results
- Community voting system

**Planned workflow:**
1. Right-click any link
2. Security Analysis → VirusTotal → Scan URL
3. Get multi-engine analysis
4. View detection ratio

**API Key:** https://www.virustotal.com/gui/my-apikey

**Best for:**
- Multi-vendor malware detection
- File hash checking
- Comprehensive threat analysis
- Second opinion on suspicious files

---

### 4. AbuseIPDB (🔜 Coming Soon)

**What it will do:**
- Check IP reputation
- View abuse reports
- Report malicious IPs
- Get confidence scores

**Planned workflow:**
1. Right-click any link
2. Security Analysis → AbuseIPDB → Check IP
3. Extract IP from domain
4. Show reputation score

**API Key:** https://www.abuseipdb.com/account/api

**Best for:**
- IP reputation checking
- DDoS source identification
- Spam source detection
- Server security

---

### 5. Google Safe Browsing (🔜 Coming Soon)

**What it will do:**
- Check for phishing sites
- Detect malware distribution
- Identify social engineering
- Real-time threat data

**Planned workflow:**
1. Right-click any link
2. Security Analysis → Safe Browsing → Check URL
3. Get immediate threat level
4. View threat details

**API Key:** Free from Google Cloud Console

**Best for:**
- Quick phishing checks
- Malware detection
- Social engineering identification
- Real-time protection

---

## Menu Structure Evolution

### Current (v1.2.0)
```
Security Analysis
├── Scan with URLScan.io
├── NextDNS
│   ├── 🚫 Add to Blocklist
│   │   └── [Profiles...]
│   └── ✓ Add to Allowlist
│       └── [Profiles...]
└── ⚙️ Configure Tools
```

### Planned (v1.3.0)
```
Security Analysis
├── Scan with URLScan.io
├── VirusTotal
│   ├── Scan URL
│   └── Check Hash
├── Google Safe Browsing
│   └── Check URL
├── NextDNS
│   ├── 🚫 Add to Blocklist
│   │   └── [Profiles...]
│   └── ✓ Add to Allowlist
│       └── [Profiles...]
└── ⚙️ Configure Tools
```

### Future (v1.4.0+)
```
Security Analysis
├── URL Analysis
│   ├── URLScan.io
│   ├── VirusTotal
│   └── Safe Browsing
├── IP Analysis
│   ├── AbuseIPDB
│   └── Shodan Lookup
├── DNS Management
│   └── NextDNS
│       ├── 🚫 Blocklist
│       └── ✓ Allowlist
├── Breach Checking
│   └── Have I Been Pwned
└── ⚙️ Configure Tools
```

---

## Comparison Matrix

| Tool | Speed | Accuracy | Free Tier | Coverage | Integration Difficulty |
|------|-------|----------|-----------|----------|----------------------|
| URLScan.io | ⚡⚡ (15s) | ⭐⭐⭐⭐ | 50/day | URLs | ✅ Easy |
| NextDNS | ⚡⚡⚡ (Instant) | ⭐⭐⭐⭐⭐ | Unlimited | Domains | ✅ Easy |
| VirusTotal | ⚡ (30-60s) | ⭐⭐⭐⭐⭐ | 4/min | URLs/Files | ⚠️ Medium |
| AbuseIPDB | ⚡⚡⚡ (Instant) | ⭐⭐⭐⭐ | 1000/day | IPs | ✅ Easy |
| Safe Browsing | ⚡⚡⚡ (Instant) | ⭐⭐⭐⭐ | 10K/day | URLs | ✅ Easy |

---

## Use Case Scenarios

### Scenario 1: Suspicious Email Link
**Workflow:**
1. URLScan.io: Scan the link to see where it really goes
2. Safe Browsing: Quick phishing check
3. VirusTotal: Multi-engine analysis
4. If malicious → NextDNS: Add to blocklist

### Scenario 2: Ad-Heavy Website
**Workflow:**
1. Browse website, note annoying ad domains
2. NextDNS: Right-click ad links → Add to blocklist
3. Ads blocked across all devices immediately

### Scenario 3: Investigating IP
**Workflow:**
1. Get IP from suspicious connection
2. AbuseIPDB: Check reputation score
3. Shodan: Look up open ports and services
4. If malicious → Block at firewall level

### Scenario 4: Downloaded File
**Workflow:**
1. Get file hash (SHA256)
2. VirusTotal: Check hash against database
3. View scan results from 70+ engines
4. Make informed decision about file safety

---

## API Rate Limits Summary

| Service | Free Tier Limit | Paid Options |
|---------|----------------|--------------|
| URLScan.io | 50 scans/day | Enterprise plans available |
| NextDNS | Unlimited API calls | Premium: $1.99/month |
| VirusTotal | 4 requests/min | Premium: 5€/month |
| AbuseIPDB | 1,000 checks/day | Premium: Various tiers |
| Safe Browsing | 10,000 queries/day | Higher quotas available |

---

## Privacy Considerations

### Data Sent to Services

| Service | What Gets Sent | Stored by Service? |
|---------|---------------|-------------------|
| URLScan.io | Full URL | Yes (per visibility setting) |
| NextDNS | Domain only | Yes (in your lists) |
| VirusTotal | URL or file hash | Yes (public) |
| AbuseIPDB | IP address | Yes (public) |
| Safe Browsing | URL hash | Temporary |

### Recommendations
- **Public scans**: Use for general website checking
- **Private scans**: Use for sensitive/proprietary URLs
- **Local-only**: For highly sensitive content, don't use external services

---

## Getting Started Guide

### Quick Start (5 minutes)
1. **Install extension** from Mozilla Add-ons
2. **Click toolbar icon** to open settings
3. **Add URLScan.io API key** (free signup)
4. **Save settings**
5. **Right-click any link** to use

### Full Setup (15 minutes)
1. **Install extension**
2. **Get URLScan.io API key**: https://urlscan.io/user/signup
3. **Get NextDNS API key**: https://my.nextdns.io/signup
4. **Configure extension** with both keys
5. **Test URLScan**: Right-click → Scan
6. **Test NextDNS**: Right-click → Add to blocklist
7. **Check NextDNS dashboard** to verify

### Power User Setup (30 minutes)
1. Complete full setup above
2. **Create multiple NextDNS profiles**: Personal, Family, Work
3. **Configure tags** for URLScan scans
4. **Set scan visibility** preferences
5. **Test all features** thoroughly
6. **Set up Firefox Sync** to share settings across devices

---

## FAQ

### Q: Do I need all API keys?
**A:** No! Each integration is optional. Use only what you need.

### Q: Are API keys free?
**A:** Yes! All services offer free tiers sufficient for personal use.

### Q: Can I use this on multiple devices?
**A:** Yes! Settings sync via Firefox Sync if enabled.

### Q: Does this slow down browsing?
**A:** No! Scans only happen when you manually trigger them.

### Q: Is my data private?
**A:** API keys stay local. URLs are only sent when you actively scan them.

### Q: Can I remove domains from NextDNS lists?
**A:** Not yet in the extension. Visit NextDNS dashboard for now. Coming in future version!

---

## Contributing Ideas

Want to suggest a new security tool integration? Consider:

### Good Candidates
✅ Free or freemium API  
✅ Security/privacy focused  
✅ Simple API authentication  
✅ Useful for daily browsing  
✅ Doesn't require complex setup  

### Examples of Good Suggestions
- **Have I Been Pwned**: Check for data breaches
- **PhishTank**: Community phishing database  
- **Shodan**: Device/service lookup
- **AlienVault OTX**: Threat intelligence

### How to Suggest
Email: info@paulrutten.nl with:
- Tool name and website
- What it does
- Why it's useful
- API documentation link

---

**Last Updated**: Version 1.2.0  
**Maintained by**: Paul Rutten  
**License**: For use with respective service APIs
