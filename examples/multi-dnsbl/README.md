# Multiple DNSBL Providers Example

This example shows how to check client IPs against multiple DNS blacklist providers.

## Providers

| Provider | Domain | Blocks |
|----------|--------|--------|
| Dan.me.uk | `.torexit.dan.me.uk` | Tor exit nodes |
| Tor Project | `.exitlist.torproject.org` | Tor exit nodes |
| Spamhaus XBL | `xbl.spamhaus.org` | Exploits/botnets |
| Spamhaus ZEN | `zen.spamhaus.org` | Combined list |

## Critical: Matching track-sc and sc_index

When using multiple DNSBL providers with separate stick-tables, the `sc_index` parameter **must match** the `track-sc` index used for each table:

```haproxy
# track-sc0 → sc_index 0
# track-sc1 → sc_index 1
# track-sc2 → sc_index 2

http-request track-sc0 src table st_tor
http-request track-sc1 src table st_spam

http-request lua.dnsbl_query st_tor .torexit.dan.me.uk "" "" 0   # matches track-sc0
http-request lua.dnsbl_query st_spam xbl.spamhaus.org "" "" 1    # matches track-sc1
```

If `sc_index` doesn't match, the gpc counters will be incremented on the wrong stick-table entry, and caching will not work correctly.

## Strategy Options

### 1. Block All Matches

Use separate stick-tables and block from all:

```haproxy
http-request track-sc0 src table st_tor_dan
http-request track-sc1 src table st_tor_project
http-request track-sc2 src table st_spamhaus

http-request lua.dnsbl_query st_tor_dan .torexit.dan.me.uk "" "" 0
http-request lua.dnsbl_query st_tor_project .exitlist.torproject.org "" "" 1
http-request lua.dnsbl_query st_spamhaus xbl.spamhaus.org "" "" 2

http-request lua.dnsbl_block st_tor_dan
http-request lua.dnsbl_block st_tor_project
http-request lua.dnsbl_block st_spamhaus
```

### 2. Block Some, Log Others

Only block Tor, but log Spamhaus matches:

```haproxy
http-request track-sc0 src table st_tor
http-request track-sc1 src table st_spam

http-request lua.dnsbl_query st_tor .torexit.dan.me.uk "" "" 0
http-request lua.dnsbl_query st_spam xbl.spamhaus.org "" "" 1

# Only block Tor
http-request lua.dnsbl_block st_tor
# Spamhaus headers logged but not blocked
```

### 3. Custom Handling with ACLs

```haproxy
acl is_tor req.hdr(X-DNSBL-Action) -m sub DENY

# Redirect Tor users
http-request redirect location /tor-notice.html if is_tor
```

## Considerations

### Performance
- Each DNSBL adds a potential DNS lookup
- Use caching (stick-tables) to minimize lookups
- Consider longer TTLs for stable lists (Tor lists)

### False Positives
- More lists = more potential false positives
- Spamhaus PBL has higher false positive rate
- Monitor and adjust based on your needs

### Stick-Table Design

**Separate tables (recommended):**
```haproxy
backend st_tor    # For Tor lists
backend st_spam   # For Spamhaus

# Remember: each table needs its own track-sc index and matching sc_index parameter
http-request track-sc0 src table st_tor
http-request track-sc1 src table st_spam
http-request lua.dnsbl_query st_tor .torexit.dan.me.uk "" "" 0
http-request lua.dnsbl_query st_spam xbl.spamhaus.org "" "" 1
```

**Single table (simpler but less granular):**
```haproxy
backend st_dnsbl  # Shared for all

# Only one track-sc needed, sc_index can be omitted (defaults to 0)
http-request track-sc0 src table st_dnsbl
http-request lua.dnsbl_query st_dnsbl .torexit.dan.me.uk "" ""
http-request lua.dnsbl_query st_dnsbl xbl.spamhaus.org "" ""
# Note: Last lookup result wins in cache (both queries update the same gpc counters)
```

**Important:** When using separate tables with different `track-sc` indices, you **must** pass the corresponding `sc_index` parameter to `dnsbl_query`. Without it, all queries default to `sc0`, which means only the first table's counters get updated correctly. This will cause caching to fail for the other tables.

## Testing

```bash
# Check headers from all lookups
curl -v http://localhost/ 2>&1 | grep X-DNSBL

# Note: Headers are overwritten by each dnsbl_query
# Only the last lookup's headers will be visible
```
