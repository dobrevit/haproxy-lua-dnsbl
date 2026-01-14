# Basic DNSBL Example

This is the simplest possible DNSBL configuration for HAProxy.

## What This Does

- Blocks Tor exit nodes using the dan.me.uk DNSBL
- Uses direct client IP (no proxy in front)
- Caches results for 30 minutes

## Prerequisites

1. HAProxy with Lua support
2. DNSBL module installed at `/usr/share/lua/5.3/dnsbl.lua`
3. Dependencies: `utils.lua`, `socket`, `inspect.lua`

## Usage

```bash
# Test configuration syntax
haproxy -c -f haproxy.cfg

# Run HAProxy
haproxy -f haproxy.cfg

# Test with curl
curl -v http://localhost/
```

## Verification

Check the response headers:

```bash
curl -s -D - http://localhost/ -o /dev/null | grep X-DNSBL
```

Expected output for non-Tor IP:
```
X-DNSBL-Action: DNSBL-LOOKUP-ALLOW
X-DNSBL-Is-Allowed: 1
X-DNSBL-Version: 0.4.0
X-DNSBL-Client-IP: 127.0.0.1
X-DNSBL-Query: 1.0.0.127.torexit.dan.me.uk
```

## Configuration Breakdown

```haproxy
# Cache DNSBL results
backend st_dnsbl_cache
    stick-table type ipv6 size 1m expire 30m store gpc0,gpc1

frontend http-in
    # Track IPs (required for caching)
    http-request track-sc0 src table st_dnsbl_cache

    # Perform lookup
    http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk "" ""

    # Block if blacklisted
    http-request lua.dnsbl_block st_dnsbl_cache
```
