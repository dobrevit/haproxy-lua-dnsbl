# Troubleshooting Guide

This guide helps you diagnose and fix common issues with the HAProxy Lua DNSBL module.

## Quick Diagnostics

### Check if DNSBL Module is Loaded

```bash
# Look for Lua loading errors in HAProxy startup
journalctl -u haproxy | grep -i lua

# Or check HAProxy logs
grep -i "lua\|dnsbl" /var/log/haproxy.log
```

### Test HAProxy Configuration

```bash
haproxy -c -f /etc/haproxy/haproxy.cfg
```

### Check DNSBL Headers

```bash
curl -v http://localhost/ 2>&1 | grep -i x-dnsbl
```

---

## Common Issues

### Issue: "lua-load: Failed to load file"

**Symptoms:**
```
[ALERT] ... : parsing [haproxy.cfg:5] : lua-load: Failed to load file 'dnsbl.lua'
```

**Causes and Solutions:**

1. **File not found:**
   ```bash
   # Check if file exists
   ls -la /usr/share/lua/5.3/dnsbl.lua

   # Use absolute path in config
   lua-load /usr/share/lua/5.3/dnsbl.lua
   ```

2. **Missing dependencies:**
   ```bash
   # Test loading in Lua directly
   lua5.3 -e "require('dnsbl')"

   # If error, install missing dependencies
   # For utils.lua:
   wget -O /usr/share/lua/5.3/utils.lua \
     https://raw.githubusercontent.com/dobrevit/haproxy-lua-utils/main/src/utils.lua

   # For inspect.lua:
   wget -O /usr/share/lua/5.3/inspect.lua \
     https://raw.githubusercontent.com/kikito/inspect.lua/master/inspect.lua
   ```

3. **Permission issues:**
   ```bash
   chmod 644 /usr/share/lua/5.3/dnsbl.lua
   chown root:root /usr/share/lua/5.3/dnsbl.lua
   ```

---

### Issue: "No backend with stick-table"

**Symptoms:**
```
[DEBUG] ... : No st_dnsbl_cache backend with stick-table within
```

**Solutions:**

1. **Create the backend:**
   ```haproxy
   backend st_dnsbl_cache
       stick-table type ipv6 size 1m expire 30m store gpc0,gpc1
   ```

2. **Check backend name matches:**
   ```haproxy
   # These must match:
   backend st_dnsbl_cache  # ← Backend name
       stick-table ...

   http-request lua.dnsbl_query st_dnsbl_cache ...  # ← Same name here
   ```

---

### Issue: "stick-table type 'ip' not supported"

**Symptoms:**
```
stick-table type 'ip' not supported. Use 'type ipv6' instead (supports both IPv4 and IPv6)
```

**Solution:**

Change your stick-table type from `ip` to `ipv6`:

```haproxy
# Before (not supported)
backend st_dnsbl_cache
    stick-table type ip size 1m expire 30m store gpc0,gpc1

# After (correct)
backend st_dnsbl_cache
    stick-table type ipv6 size 1m expire 30m store gpc0,gpc1
```

**Why:** The `ipv6` type handles both IPv4 and IPv6 addresses. IPv4 addresses are automatically converted to IPv4-mapped IPv6 format (`::ffff:x.x.x.x`) internally.

---

### Issue: "stktbl_lookup error: No entry found"

**Symptoms:**
```
[DEBUG] ... : stktbl_lookup error: No entry found. Most likely there isn't track-sc0 set
```

**Solution:**

Add `track-sc0` before the DNSBL query:

```haproxy
frontend http-in
    bind *:80

    # This line is required!
    http-request track-sc0 src table st_dnsbl_cache

    http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk "" ""
```

---

### Issue: DNS Lookups Failing

**Symptoms:**
- `X-DNSBL-Action: DNSBL-ERROR-ALLOW` on all requests
- Debug messages about DNS resolution failures

**Diagnostics:**

```bash
# Test DNS resolution manually
dig 1.2.0.192.torexit.dan.me.uk

# Check if DNS is working
nslookup google.com

# Check HAProxy's DNS settings
cat /etc/resolv.conf
```

**Solutions:**

1. **Configure a working DNS resolver:**
   ```bash
   # /etc/resolv.conf
   nameserver 8.8.8.8
   nameserver 1.1.1.1
   ```

2. **Use a local resolver for better performance:**
   ```bash
   # Install dnsmasq or unbound
   apt install dnsmasq
   systemctl start dnsmasq

   # Point to localhost
   echo "nameserver 127.0.0.1" > /etc/resolv.conf
   ```

---

### Issue: All Requests Being Blocked

**Symptoms:**
- Every request returns 401
- `X-DNSBL-Action: DNSBL-CACHE-DENY` for all IPs

**Diagnostics:**

```bash
# Check stick-table contents
echo "show table st_dnsbl_cache" | socat stdio /var/run/haproxy/admin.sock
```

**Solutions:**

1. **Clear the stick-table:**
   ```bash
   echo "clear table st_dnsbl_cache" | socat stdio /var/run/haproxy/admin.sock
   ```

2. **Check if your own IP is in a blacklist:**
   ```bash
   # Replace with your IP
   dig 1.2.168.192.torexit.dan.me.uk
   ```

3. **Verify the DNSBL domain:**
   ```haproxy
   # Make sure domain starts with a dot
   http-request lua.dnsbl_query st_cache .torexit.dan.me.uk "" ""
   #                                    ^ dot here
   ```

---

### Issue: No Requests Being Blocked

**Symptoms:**
- Known Tor exit IPs pass through
- `X-DNSBL-Action: DNSBL-LOOKUP-ALLOW` for known blacklisted IPs

**Diagnostics:**

```bash
# Test with a known Tor exit node (get current list from torproject.org)
# This is an example - use a current Tor exit IP
curl -H "X-Forwarded-For: 185.220.101.1" http://localhost/
```

**Solutions:**

1. **Check if you're querying the right DNSBL:**
   ```bash
   # Verify the IP is actually listed
   dig 1.101.220.185.torexit.dan.me.uk
   # Should return 127.0.0.100 if listed
   ```

2. **Ensure both actions are present:**
   ```haproxy
   http-request lua.dnsbl_query st_cache .torexit.dan.me.uk "" ""
   http-request lua.dnsbl_block st_cache  # ← Don't forget this!
   ```

3. **Check if header extraction is working:**
   ```bash
   # Test X-Forwarded-For extraction
   curl -v -H "X-Forwarded-For: 185.220.101.1" http://localhost/ 2>&1 | grep X-DNSBL-Client-IP
   # Should show the X-Forwarded-For IP, not your real IP
   ```

---

### Issue: Wrong IP Being Checked

**Symptoms:**
- `X-DNSBL-Client-IP` header shows wrong IP
- Behind proxy but checking proxy IP instead of client IP

**Solutions:**

1. **Configure header extraction:**
   ```haproxy
   # Get IP from X-Forwarded-For header
   http-request lua.dnsbl_query st_cache .torexit.dan.me.uk "" X-Forwarded-For
   ```

2. **Handle multiple IPs in X-Forwarded-For:**
   ```haproxy
   # Extract first IP only
   http-request set-var(txn.real_ip) hdr(X-Forwarded-For),word(1,",")
   http-request lua.dnsbl_query st_cache .torexit.dan.me.uk txn.real_ip ""
   ```

3. **Track the correct IP in stick-table:**
   ```haproxy
   # Track header IP, not socket IP
   http-request track-sc0 hdr(X-Forwarded-For) table st_cache
   ```

---

### Issue: Spamhaus Rate Limiting

**Symptoms:**
- `X-DNSBL-Description: Excessive number of queries`
- `X-DNSBL-Description: Query via public/open resolver`

**Solutions:**

1. **Use your own recursive resolver:**
   ```bash
   # Don't use public DNS (8.8.8.8, 1.1.1.1) for Spamhaus
   # Set up local resolver
   apt install unbound
   ```

2. **Increase cache TTL:**
   ```haproxy
   backend st_spam_cache
       stick-table type ipv6 size 1m expire 1h store gpc0,gpc1
       #                              ^^^^ longer expiry
   ```

3. **Consider Spamhaus Data Query Service:**
   - For high-volume use, register at spamhaus.org

---

## Enabling Debug Logging

The module has commented debug statements. To enable them:

1. **Edit dnsbl.lua:**
   ```lua
   -- Change lines like:
   --txn:Debug(string.format("DNSBL: client IP: %s\n", client_ip))

   -- To:
   txn:Debug(string.format("DNSBL: client IP: %s\n", client_ip))
   ```

2. **Reload HAProxy:**
   ```bash
   systemctl reload haproxy
   ```

3. **View debug output:**
   ```bash
   journalctl -u haproxy -f
   ```

---

## Stick-Table Commands

### View Table Contents

```bash
echo "show table st_dnsbl_cache" | socat stdio /var/run/haproxy/admin.sock
```

Output format:
```
# table: st_dnsbl_cache, type: ipv6, size:1048576, used:2
0x1234567890: key=::ffff:192.0.2.1 use=0 exp=1800000 gpc0=1 gpc1=0
0x1234567891: key=::ffff:198.51.100.1 use=0 exp=1800000 gpc0=0 gpc1=1
```

### Clear Specific Entry

```bash
echo "clear table st_dnsbl_cache key ::ffff:192.0.2.1" | socat stdio /var/run/haproxy/admin.sock
```

### Clear Entire Table

```bash
echo "clear table st_dnsbl_cache" | socat stdio /var/run/haproxy/admin.sock
```

### Set Entry Manually (for testing)

```bash
# Set gpc0 (allow counter)
echo "set table st_dnsbl_cache key ::ffff:192.0.2.1 data.gpc0 1" | socat stdio /var/run/haproxy/admin.sock
```

---

## Testing DNSBL Lookups Manually

### Dan.me.uk Tor List

```bash
# Format: reversed_ip.torexit.dan.me.uk
dig 1.101.220.185.torexit.dan.me.uk

# Listed response: 127.0.0.100
# Not listed: NXDOMAIN
```

### Tor Project List

```bash
dig 1.101.220.185.80.exitlist.torproject.org

# Listed response: 127.0.0.2
# Not listed: NXDOMAIN
```

### Spamhaus XBL

```bash
dig 1.101.220.185.xbl.spamhaus.org

# Various 127.0.0.x responses
# Not listed: NXDOMAIN
```

---

## Performance Issues

### Slow First Requests

**Cause:** DNS lookup latency

**Solutions:**
1. Use a local caching DNS resolver
2. Increase stick-table expiry time
3. Pre-warm cache with known IPs

### High Memory Usage

**Cause:** Large stick-table

**Solutions:**
1. Reduce stick-table size:
   ```haproxy
   stick-table type ipv6 size 500k expire 15m store gpc0,gpc1
   ```

2. Use shorter expiry time

### High CPU Usage

**Cause:** Too many DNS lookups (cache misses)

**Solutions:**
1. Increase stick-table size (more cache hits)
2. Increase expiry time
3. Batch similar IPs (e.g., /24 networks) - requires code modification

---

## Getting Help

If you're still having issues:

1. **Check GitHub Issues:** https://github.com/dobrevit/haproxy-lua-dnsbl/issues

2. **Open a new issue** with:
   - HAProxy version (`haproxy -v`)
   - Lua version (`lua -v`)
   - Relevant HAProxy configuration (sanitized)
   - Debug log output
   - Steps to reproduce

3. **HAProxy mailing list:** For general HAProxy questions
