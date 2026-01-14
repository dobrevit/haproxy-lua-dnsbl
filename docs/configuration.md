# Configuration Guide

This guide covers everything you need to configure HAProxy Lua DNSBL module.

## Prerequisites

### 1. HAProxy with Lua Support

Ensure HAProxy is compiled with Lua support:

```bash
haproxy -vv | grep Lua
# Should show: Built with Lua version
```

### 2. Required Lua Libraries

Install the required dependencies in your Lua path (e.g., `/usr/share/lua/5.3/`):

| Library | Repository | Purpose |
|---------|------------|---------|
| `utils.lua` | [haproxy-lua-utils](https://github.com/dobrevit/haproxy-lua-utils) | IP address utilities |
| `socket` | LuaSocket | DNS resolution (usually pre-installed) |
| `inspect.lua` | [inspect.lua](https://github.com/kikito/inspect.lua) | Debug output (optional) |

```bash
# Example installation
cd /usr/share/lua/5.3/
wget https://raw.githubusercontent.com/dobrevit/haproxy-lua-utils/main/src/utils.lua
wget https://raw.githubusercontent.com/kikito/inspect.lua/master/inspect.lua
```

### 3. Install DNSBL Module

```bash
cp src/dnsbl.lua /usr/share/lua/5.3/dnsbl.lua
```

---

## Basic Configuration

### Step 1: Load the Lua Module

Add to your HAProxy configuration's `global` section:

```haproxy
global
    lua-load /usr/share/lua/5.3/dnsbl.lua
    # Or if in Lua path:
    # lua-load dnsbl.lua
```

### Step 2: Create a Stick-Table Backend

The stick-table caches DNSBL lookup results:

```haproxy
backend st_dnsbl_cache
    # IPv6 type supports both IPv4 and IPv6 addresses
    stick-table type ipv6 size 1m expire 30m store gpc0,gpc1
```

**Parameters explained:**

| Parameter | Value | Description |
|-----------|-------|-------------|
| `type` | `ipv6` | Key type - use ipv6 for dual-stack support |
| `size` | `1m` | Maximum entries (1 million) |
| `expire` | `30m` | Cache TTL (30 minutes) |
| `store` | `gpc0,gpc1` | Counters: gpc0=allowed, gpc1=blocked |

### Step 3: Configure IP Tracking

Track client IPs in the stick-table:

```haproxy
frontend http-in
    bind *:80

    # Track source IP in stick-table
    http-request track-sc0 src table st_dnsbl_cache
```

### Step 4: Add DNSBL Actions

```haproxy
frontend http-in
    bind *:80

    http-request track-sc0 src table st_dnsbl_cache

    # Perform DNSBL lookup
    http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk "" ""

    # Block blacklisted IPs
    http-request lua.dnsbl_block st_dnsbl_cache

    default_backend servers
```

---

## Complete Configuration Example

```haproxy
global
    log stdout format raw local0
    lua-load /usr/share/lua/5.3/dnsbl.lua

defaults
    log global
    mode http
    option httplog
    timeout connect 5s
    timeout client 30s
    timeout server 30s

# Stick-table for caching DNSBL results
backend st_dnsbl_cache
    stick-table type ipv6 size 1m expire 30m store gpc0,gpc1

# Your backend servers
backend servers
    server web1 127.0.0.1:8080 check

# Frontend with DNSBL protection
frontend http-in
    bind *:80

    # Track source IP
    http-request track-sc0 src table st_dnsbl_cache

    # DNSBL lookup and blocking
    http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk "" ""
    http-request lua.dnsbl_block st_dnsbl_cache

    default_backend servers
```

---

## Configuration Options

### dnsbl_query Parameters

```haproxy
http-request lua.dnsbl_query <backend> <domain> <src_var> <src_header> [sc_index]
```

| Parameter | Required | Example | Description |
|-----------|----------|---------|-------------|
| `backend` | Yes | `st_dnsbl_cache` | Backend with stick-table |
| `domain` | Yes | `.torexit.dan.me.uk` | DNSBL domain |
| `src_var` | No | `txn.real_ip` | Variable with client IP (use `""` to skip) |
| `src_header` | No | `X-Forwarded-For` | Header with client IP (use `""` to skip) |
| `sc_index` | No | `0`, `1`, or `2` | Track-sc index for gpc counters (must match `track-sc` index, defaults to 0) |

### Supported DNSBL Domains

| Domain | Description |
|--------|-------------|
| `.torexit.dan.me.uk` | Dan.me.uk Tor exit list |
| `.exitlist.torproject.org` | Tor Project exit list |
| `xbl.spamhaus.org` | Spamhaus XBL (exploits) |
| `zen.spamhaus.org` | Spamhaus ZEN (combined) |
| `sbl.spamhaus.org` | Spamhaus SBL (spam) |
| `pbl.spamhaus.org` | Spamhaus PBL (policy) |

---

## Behind a Reverse Proxy

When HAProxy is behind another proxy (nginx, CDN, etc.), use the `src_header` parameter:

```haproxy
frontend http-in
    bind *:80

    http-request track-sc0 hdr(X-Forwarded-For) table st_dnsbl_cache

    # Get client IP from X-Forwarded-For header
    http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk "" X-Forwarded-For

    http-request lua.dnsbl_block st_dnsbl_cache

    default_backend servers
```

### Using X-Real-IP Header

```haproxy
http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk "" X-Real-IP
```

### Using a Custom Variable

```haproxy
# Extract first IP from X-Forwarded-For (handles multiple proxies)
http-request set-var(txn.real_ip) hdr(X-Forwarded-For),word(1,",")

http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk txn.real_ip ""
```

---

## Multiple DNSBL Providers

You can query multiple blacklists using separate stick-tables:

```haproxy
# Separate stick-tables per provider
backend st_tor_cache
    stick-table type ipv6 size 500k expire 1h store gpc0,gpc1

backend st_spam_cache
    stick-table type ipv6 size 500k expire 30m store gpc0,gpc1

frontend http-in
    bind *:80

    # Track IPs using different track-sc indices
    http-request track-sc0 src table st_tor_cache
    http-request track-sc1 src table st_spam_cache

    # Check Tor exit list (sc_index 0 matches track-sc0)
    http-request lua.dnsbl_query st_tor_cache .torexit.dan.me.uk "" "" 0

    # Check Spamhaus XBL (sc_index 1 matches track-sc1)
    http-request lua.dnsbl_query st_spam_cache xbl.spamhaus.org "" "" 1

    # Block if either list matched
    http-request lua.dnsbl_block st_tor_cache
    http-request lua.dnsbl_block st_spam_cache

    default_backend servers
```

**Important:** The `sc_index` parameter must match the `track-sc` index used for each stick-table. If they don't match, the gpc counters will be incremented on the wrong stick-table entry, causing the cache to malfunction.

---

## Configurable Track-SC Index

By default, the module uses `sc0`. To use a different index, pass the `sc_index` parameter (5th parameter):

```haproxy
# Using sc1 instead of sc0
http-request track-sc1 src table st_dnsbl_cache
http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk "" "" 1
```

The `sc_index` parameter accepts values `0`, `1`, or `2`, corresponding to `track-sc0`, `track-sc1`, and `track-sc2`.

---

## Stick-Table Sizing Guide

| Traffic Level | Size | Expire | Memory (approx) |
|--------------|------|--------|-----------------|
| Low (< 10k unique IPs/day) | `100k` | `1h` | ~20 MB |
| Medium (10k-100k) | `500k` | `30m` | ~100 MB |
| High (100k-1M) | `1m` | `15m` | ~200 MB |
| Very High (> 1M) | `5m` | `10m` | ~1 GB |

**Calculation:** Each entry uses approximately 200 bytes.

---

## Logging Configuration

Add DNSBL headers to your log format:

```haproxy
defaults
    log-format "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r dnsbl_action:%[req.hdr(X-DNSBL-Action)] dnsbl_allowed:%[req.hdr(X-DNSBL-Is-Allowed)]"
```

---

## Health Checking

You may want to exclude health check endpoints from DNSBL:

```haproxy
frontend http-in
    bind *:80

    # Skip DNSBL for health checks
    acl is_health_check path /health /ready /live

    http-request track-sc0 src table st_dnsbl_cache if !is_health_check
    http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk "" "" if !is_health_check
    http-request lua.dnsbl_block st_dnsbl_cache if !is_health_check

    default_backend servers
```

---

## Performance Tuning

### DNS Resolver Configuration

Use a local caching DNS resolver for best performance:

```bash
# /etc/resolv.conf
nameserver 127.0.0.1  # Local resolver (dnsmasq, unbound, etc.)
nameserver 8.8.8.8    # Fallback
```

### Timeouts

The Lua socket library uses system defaults. For production, consider running a local DNS resolver to minimize latency.

### Stick-Table Peers

For multi-node HAProxy setups, sync stick-tables between nodes:

```haproxy
peers dnsbl_peers
    peer haproxy1 192.168.1.10:10000
    peer haproxy2 192.168.1.11:10000

backend st_dnsbl_cache
    stick-table type ipv6 size 1m expire 30m store gpc0,gpc1 peers dnsbl_peers
```

---

## Validation

Test your configuration:

```bash
# Syntax check
haproxy -c -f /etc/haproxy/haproxy.cfg

# Test with a known Tor exit IP (check torproject.org for current list)
curl -H "X-Forwarded-For: <tor-exit-ip>" http://localhost/

# Check headers returned
curl -v http://localhost/ 2>&1 | grep X-DNSBL
```

---

## Troubleshooting

See [Troubleshooting Guide](troubleshooting.md) for common issues and solutions.
