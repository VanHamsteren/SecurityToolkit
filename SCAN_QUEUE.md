# URLScan.io Scan Queue Feature

## Overview

The Scan Queue allows you to collect URLs throughout the day and process them all at once in a batch, with automatic rate limiting to respect URLScan.io API limits.

## Features

- ✅ **Add URLs to Queue**: Right-click any link to add to queue
- ✅ **Batch Processing**: Scan all queued URLs with one click
- ✅ **Automatic Rate Limiting**: 2.5 second delays between scans
- ✅ **Progress Tracking**: See status of each URL
- ✅ **Queue Management**: View, remove, or clear queued URLs
- ✅ **Duplicate Detection**: Won't add same URL twice
- ✅ **Status Monitoring**: Pending, Scanning, Completed, Failed

## How to Use

### Method 1: Add from Context Menu

1. **Right-click any link**
2. **Security Analysis → URLScan.io → ➕ Add to Scan Queue**
3. Notification confirms URL added
4. Repeat for all URLs you want to scan

### Method 2: Process Queue from Context Menu

1. After adding URLs to queue
2. **Right-click any link**
3. **Security Analysis → URLScan.io → 🚀 Process Queue (X URLs)**
4. Queue processing starts automatically

### Method 3: Manage Queue from Settings

1. **Click extension icon** in toolbar
2. **Scroll to "URLScan.io Scan Queue" section**
3. See all queued URLs with status
4. **Click "🚀 Process Queue"** to start scanning
5. Watch progress in real-time

## Menu Structure

```
Security Analysis
└── URLScan.io
    ├── 🔍 Scan Now (immediate scan)
    ├── ➕ Add to Scan Queue
    └── 🚀 Process Queue (5 URLs) [appears when queue has items]
```

## Queue Management Interface

### Settings Page Section

The queue management section shows:

**When Queue is Empty:**
```
No URLs in scan queue. Right-click any link and select 
"Add to Scan Queue" to get started.
```

**When Queue Has Items:**
```
┌─────────────────────────────────────────────────────┐
│ 5 URL(s) in Queue        [🔄 Refresh] [🗑️ Clear All] │
├─────────────────────────────────────────────────────┤
│ https://example.com/suspicious       ⏳ Pending  [×]│
│ https://malware-site.com             ⏳ Pending  [×]│
│ https://phishing.org/fake            ✓ Completed [×]│
│ https://cryptoscam.io                ✗ Failed    [×]│
│ https://another-bad-site.com         🔍 Scanning [×]│
├─────────────────────────────────────────────────────┤
│                [🚀 Process Queue]                    │
└─────────────────────────────────────────────────────┘

Rate Limiting: URLs are scanned with 2.5 second delays
```

### Status Indicators

| Status | Icon | Color | Meaning |
|--------|------|-------|---------|
| **Pending** | ⏳ | Blue | Waiting to be scanned |
| **Scanning** | 🔍 | Yellow | Currently being scanned |
| **Completed** | ✓ | Green | Successfully scanned |
| **Failed** | ✗ | Red | Scan failed (see error) |

## Use Cases

### Use Case 1: Phishing Investigation

**Scenario**: Receive suspicious email with multiple links

1. Open phishing email
2. Right-click first link → **Add to Scan Queue**
3. Right-click second link → **Add to Scan Queue**
4. Continue for all links (5-10 URLs)
5. Open extension settings
6. Click **Process Queue**
7. Go get coffee ☕
8. Come back to completed scans

**Time saved**: Instead of waiting 15 seconds per scan × 10 URLs = 2.5 minutes of manual waiting

### Use Case 2: Threat Intelligence Feed

**Scenario**: Reading security blog with IOCs

1. Browse threat intelligence article
2. Each suspicious URL mentioned → **Add to Queue**
3. Continue reading
4. End of article → **Process Queue**
5. All URLs scanned while you continue work

### Use Case 3: Daily Security Review

**Scenario**: Security team daily routine

**Morning**: Collect URLs
- Check email → Queue suspicious links
- Browse forums → Queue reported malware
- Review tickets → Queue customer-reported URLs

**Afternoon**: Process batch
- Open settings
- Click **Process Queue (23 URLs)**
- Review all results together
- Add malicious domains to NextDNS blocklist

### Use Case 4: Multiple Sources

**Scenario**: URLs from various places

- Email links → Queue
- Slack/Teams messages → Queue
- Reddit posts → Queue
- Twitter/X links → Queue
- Process all at once

## Rate Limiting

### Why It Matters

URLScan.io has rate limits:
- **Free tier**: ~50 scans/day
- **Per minute**: Limited to prevent abuse
- **HTTP 429**: Returns error if exceeded

### How Extension Handles It

**Automatic Delays:**
- 2.5 seconds between each scan
- Safe for free tier users
- Prevents rate limit errors

**Example Timeline:**
```
00:00 - Scan URL 1
00:02.5 - Scan URL 2
00:05.0 - Scan URL 3
00:07.5 - Scan URL 4
...
```

For 10 URLs: ~25 seconds total (vs 150+ seconds manual)

### Rate Limit Errors

If you hit a rate limit:
- Current scan fails
- Status shows "Failed"
- Wait a few minutes
- Click **Process Queue** again
- Only failed items are retried

## Queue Features

### Duplicate Detection

**Prevents duplicates:**
```
Right-click example.com → Add to Queue ✓
Right-click example.com → "Already in queue" ⚠️
```

### Persistent Storage

Queue survives:
- ✅ Browser restarts
- ✅ Extension reloads
- ✅ Computer shutdown

### Max Queue Size

Recommended: **50 URLs** (free tier daily limit)

No hard limit, but consider:
- URLScan.io daily quota
- Processing time
- Browser memory

### Progress Notifications

During processing:
```
🚀 Processing Queue
Starting to scan 10 URLs...

🔍 Scanning
Processing 3/10: https://example.com...

🔍 Scanning
Processing 4/10: https://another-site.com...

✓ Queue Complete!
Successfully scanned all 10 URLs
```

## Queue Management

### View Queue

**Settings Page:**
- See all URLs
- Check status
- View errors

**Context Menu:**
- Shows count: "Process Queue (5 URLs)"

### Remove Individual Items

1. Open settings
2. Find URL in queue
3. Click **×** button
4. URL removed immediately

### Clear All

1. Open settings
2. Click **🗑️ Clear All**
3. Confirm dialog
4. Entire queue cleared

### Refresh

1. Click **🔄 Refresh**
2. Updates status of all items
3. Useful during processing

## Tips & Best Practices

### Tip 1: Collect Throughout Day

Don't interrupt your workflow:
- See suspicious link → Add to queue
- Continue working
- Process queue at convenient time

### Tip 2: Review Before Processing

Before clicking **Process Queue**:
- Review queued URLs
- Remove any mistakes
- Ensure all are meant to be scanned

### Tip 3: Monitor Progress

During processing:
- Keep settings page open
- Watch real-time status updates
- Auto-refreshes every 5 seconds

### Tip 4: Combine with NextDNS

Workflow:
1. Queue suspicious URLs
2. Process queue
3. Review results
4. Right-click malicious domains → Add to NextDNS

### Tip 5: Don't Overload Queue

Best practice:
- 10-20 URLs per batch
- Process regularly
- Don't queue 100+ URLs at once

## Error Handling

### Common Errors

**"Already in Queue"**
- URL was already added
- Check queue in settings
- Not an error, just info

**"Failed" Status**
- Rate limit exceeded
- Invalid API key
- Network error
- Check URLScan.io settings

**"Queue is already being processed"**
- Processing already in progress
- Wait for current batch to finish
- Don't start multiple processes

### Recovery

**If processing stops:**
1. Open settings
2. Check queue status
3. Failed items remain in queue
4. Click **Process Queue** again

**If all scans fail:**
1. Check URLScan.io API key
2. Check internet connection
3. Wait a few minutes (rate limit)
4. Try again

## Technical Details

### Storage

- **Location**: `browser.storage.local`
- **Key**: `urlscanQueue`
- **Format**: Array of objects
- **Structure**:
```javascript
{
  url: "https://example.com",
  addedAt: "2025-01-30T10:30:00.000Z",
  status: "pending", // pending|scanning|completed|failed
  uuid: "abc-123", // URLScan result UUID
  error: null // Error message if failed
}
```

### Processing Logic

```
1. Get all "pending" items from queue
2. For each item:
   a. Update status to "scanning"
   b. Submit to URLScan.io API
   c. Wait for response
   d. Update status (completed/failed)
   e. Wait 2.5 seconds
3. Show final summary
```

### API Calls

Each queued URL:
- 1 POST request to `/api/v1/scan/`
- 1 notification per URL (during processing)
- 1 final summary notification

### Performance

**Memory**: ~1KB per queued URL  
**Processing**: Minimal CPU usage  
**Network**: Only during scan submission

## Console Debugging

Enable Browser Console to see:

```javascript
// Adding to queue
Adding to URLScan queue: https://example.com
URLScan queue updated: 5 items

// Processing queue
Processing URLScan queue: 5 URLs
Scanning 1/5: https://example.com
Scanning 2/5: https://malware.com
...
Queue processing complete: 5 success, 0 failed

// Errors
Failed to scan: https://bad-url.com Error: Rate limit exceeded
```

## Keyboard Shortcuts

Currently none, but could add:
- `Alt+Q` - Add to queue
- `Alt+Shift+Q` - Process queue
- `Alt+C` - Clear queue

(Future enhancement)

## Comparison: Manual vs Queue

### Manual Scanning (Old Way)

1. Right-click link → Scan
2. **Wait 15 seconds**
3. Tab opens with results
4. Right-click next link → Scan
5. **Wait 15 seconds**
6. Another tab opens
7. Repeat 10 times...

**Time**: ~2.5 minutes of waiting  
**Effort**: High (constant attention)  
**Tabs**: 10 new tabs opened

### Queue Scanning (New Way)

1. Right-click links → Add to queue (×10)
2. Click **Process Queue**
3. **Do other work for 30 seconds**
4. 10 tabs with results

**Time**: 30 seconds unattended  
**Effort**: Low (set and forget)  
**Tabs**: 10 new tabs (same), but async

## Future Enhancements

Planned features:
- [ ] Export queue to CSV
- [ ] Import URLs from file
- [ ] Schedule queue processing
- [ ] Email results summary
- [ ] Integration with SIEM tools
- [ ] Pause/resume processing
- [ ] Priority queue
- [ ] Retry failed items automatically

## FAQ

**Q: Can I add URLs from selected text?**  
A: Not yet. Currently only works with right-click on links.

**Q: How many URLs can I queue?**  
A: No hard limit, but respect URLScan.io's daily quota (typically 50).

**Q: Does queue survive browser restart?**  
A: Yes, queue is persistent.

**Q: Can I cancel processing?**  
A: Not yet, but planned for future version.

**Q: Will processing drain my API quota?**  
A: Yes, each queued URL counts toward your daily limit.

**Q: Can I see scan results in extension?**  
A: No, results open in new tabs as before.

**Q: Is there a mobile version?**  
A: No, Firefox extension only.

---

**Version**: 1.2.0  
**Status**: Active ✅  
**Supported**: URLScan.io API v1
