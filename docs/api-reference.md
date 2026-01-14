# API Reference

Complete documentation for all functions in the HAProxy Lua DNSBL module.

## HAProxy Actions

These actions are registered with HAProxy and can be used in your configuration.

---

### lua.dnsbl_query

Performs a DNSBL lookup for the client IP address and caches the result.

**Usage in HAProxy:**
```haproxy
http-request lua.dnsbl_query <stick_table_backend> <dnsbl_domain> [src_var] [src_header] [sc_index]
```

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `stick_table_backend` | Yes | Name of the backend containing the stick-table for caching |
| `dnsbl_domain` | Yes | DNSBL domain to query (e.g., `.torexit.dan.me.uk`) |
| `src_var` | No | HAProxy variable containing the client IP (e.g., `txn.real_ip`). Use `""` to skip. |
| `src_header` | No | HTTP header containing the client IP (e.g., `X-Forwarded-For`). Use `""` to skip. |
| `sc_index` | No | Track-sc index (0, 1, or 2) for incrementing gpc counters. Must match the `track-sc` index used. Defaults to 0. |

**Client IP Resolution Order:**
1. Transaction variable `txn.dnsbl_client_ip` (if previously set)
2. Custom variable specified in `src_var`
3. HTTP header specified in `src_header`
4. Direct connection source (`txn.sf:src()`)

**Examples:**

```haproxy
# Basic usage - use direct client IP (uses track-sc0 by default)
http-request lua.dnsbl_query st_cache .torexit.dan.me.uk "" ""

# Behind a proxy - get IP from X-Forwarded-For header
http-request lua.dnsbl_query st_cache .torexit.dan.me.uk "" X-Forwarded-For

# Using a custom variable
http-request set-var(txn.client_ip) hdr(X-Real-IP)
http-request lua.dnsbl_query st_cache .torexit.dan.me.uk txn.client_ip ""

# Using track-sc1 instead of track-sc0
http-request track-sc1 src table st_cache
http-request lua.dnsbl_query st_cache .torexit.dan.me.uk "" "" 1

# Multiple DNSBL providers with separate stick-tables
# IMPORTANT: sc_index must match the track-sc index used for each table
http-request track-sc0 src table st_tor_cache
http-request track-sc1 src table st_spam_cache
http-request lua.dnsbl_query st_tor_cache .torexit.dan.me.uk "" "" 0
http-request lua.dnsbl_query st_spam_cache xbl.spamhaus.org "" "" 1
```

**Headers Set:**

| Header | Description |
|--------|-------------|
| `X-DNSBL-Action` | Result of the lookup (see below) |
| `X-DNSBL-Is-Allowed` | `1` if allowed, `0` if blocked |
| `X-DNSBL-Version` | Module version |
| `X-DNSBL-Client-IP` | IP address that was checked |
| `X-DNSBL-Query` | Full DNS query string |
| `X-DNSBL-Error` | Error message (if applicable) |
| `X-DNSBL-Zone` | Spamhaus zone (if applicable) |
| `X-DNSBL-Description` | Spamhaus description (if applicable) |

**X-DNSBL-Action Values:**

| Value | Meaning |
|-------|---------|
| `DNSBL-CACHE-ALLOW` | Cached result: IP is allowed |
| `DNSBL-CACHE-DENY` | Cached result: IP is blocked |
| `DNSBL-LOOKUP-ALLOW` | Fresh lookup: IP not in blacklist |
| `DNSBL-LOOKUP-DENY` | Fresh lookup: IP found in blacklist |
| `DNSBL-ERROR-ALLOW` | Error occurred, request allowed (fail-open) |

**Transaction Variables Set:**

| Variable | Description |
|----------|-------------|
| `txn.dnsbl_client_ip` | Client IP used for the lookup |
| `txn.dnsbl_is_allowed` | Boolean indicating if request is allowed |

---

### lua.dnsbl_block

Blocks requests from IPs that were marked as blocked by `dnsbl_query`.

**Usage in HAProxy:**
```haproxy
http-request lua.dnsbl_block <stick_table_backend>
```

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `stick_table_backend` | Yes | Name of the backend containing the stick-table |

**Behavior:**
- Checks `txn.dnsbl_is_allowed` variable set by `dnsbl_query`
- If not allowed, returns `401 Unauthorized` response
- Response includes `Denial-Reason` header

**Example:**
```haproxy
frontend http-in
    bind *:80

    # First, perform the lookup
    http-request lua.dnsbl_query st_cache .torexit.dan.me.uk "" ""

    # Then, block if necessary
    http-request lua.dnsbl_block st_cache

    default_backend servers
```

**Response on Block:**
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html
Server: DNSBL/0.4.0
Denial-Reason: DNSBL: IP found in hard banlist. BLOCK request
```

---

## Lua Module Functions

These functions are exported by the module and can be used in custom Lua code.

### _M.stktbl_lookup

Looks up an IP address in a HAProxy stick-table.

**Signature:**
```lua
local entry, err = _M.stktbl_lookup(stktbl, key)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `stktbl` | stick-table | HAProxy stick-table object |
| `key` | string | IP address to look up |

**Returns:**

| Return | Type | Description |
|--------|------|-------------|
| `entry` | table/nil | Stick-table entry with gpc0, gpc1, etc. |
| `err` | string/nil | Error message if lookup failed |

**Behavior:**
- For IPv6 stick-tables, automatically converts IPv4 addresses to IPv4-mapped IPv6 format (`::ffff:x.x.x.x`)
- Returns `nil, "Unsupported stick-table type"` for unsupported types
- Returns `nil, "No entry found"` if IP not in table

**Example:**
```lua
local st = core.backends["st_cache"].stktable
local entry, err = _M.stktbl_lookup(st, "192.0.2.1")

if entry then
    if entry.gpc0 == 1 then
        -- IP is allowed
    elseif entry.gpc1 == 1 then
        -- IP is blocked
    end
else
    -- New visitor or error
    print("Lookup error: " .. (err or "unknown"))
end
```

---

### _M.spamhaus_response

Maps Spamhaus DNSBL response codes to human-readable information.

**Signature:**
```lua
local permitted, zone, description = _M.spamhaus_response(response)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `response` | string | IP address returned by Spamhaus DNS query |

**Returns:**

| Return | Type | Description |
|--------|------|-------------|
| `permitted` | boolean | `true` if request should be allowed |
| `zone` | string/nil | Spamhaus zone (SBL, XBL, PBL) |
| `description` | string/nil | Human-readable description |

**Response Code Mappings:**

| Response | Zone | Description | Permitted |
|----------|------|-------------|-----------|
| `127.0.0.2` | SBL | Spamhaus SBL Data | false |
| `127.0.0.3` | SBL | Spamhaus SBL CSS Data | false |
| `127.0.0.4` | XBL | CBL Data | false |
| `127.0.0.9` | SBL | Spamhaus DROP/EDROP Data | false |
| `127.0.0.10` | PBL | ISP Maintained | false |
| `127.0.0.11` | PBL | Spamhaus Maintained | false |
| `127.255.255.252` | Any | Typing error in DNSBL name | false |
| `127.255.255.254` | Any | Query via public/open resolver | false |
| `127.255.255.255` | Any | Excessive number of queries | false |
| Other | - | Unknown response | true |

**Example:**
```lua
local ip = "127.0.0.4"  -- Response from Spamhaus
local permitted, zone, description = _M.spamhaus_response(ip)

if not permitted then
    print(string.format("Blocked by %s: %s", zone, description))
    -- Output: Blocked by XBL: CBL Data
end
```

---

### _M.is_blocked_response

Checks if a DNSBL response indicates the IP should be blocked.

**Signature:**
```lua
local blocked, zone, description = _M.is_blocked_response(response, dnsbl_domain)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `response` | string | IP address returned by DNSBL DNS query |
| `dnsbl_domain` | string | The DNSBL domain that was queried |

**Returns:**

| Return | Type | Description |
|--------|------|-------------|
| `blocked` | boolean | `true` if IP should be blocked |
| `zone` | string/nil | Zone/list name (for Spamhaus) |
| `description` | string/nil | Description (for Spamhaus) |

**Supported DNSBL Domains:**

| Domain | Blocked Responses |
|--------|-------------------|
| `.torexit.dan.me.uk` | `127.0.0.100` |
| `.exitlist.torproject.org` | `127.0.0.2` |
| `*.spamhaus.org` | Uses `spamhaus_response()` mapping |

**Example:**
```lua
local response = "127.0.0.100"
local domain = ".torexit.dan.me.uk"

local blocked, zone, desc = _M.is_blocked_response(response, domain)
if blocked then
    print("IP is blocked: Tor exit node detected")
end
```

---

### _M.sc_inc_gpc0

Increments gpc0 counter for the specified stick-table using configurable track-sc index.

**Signature:**
```lua
_M.sc_inc_gpc0(txn, backend, sc_index)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `txn` | transaction | HAProxy transaction object |
| `backend` | string | Backend name with stick-table |
| `sc_index` | number | Track-sc index (0, 1, or 2) |

**Example:**
```lua
-- Increment gpc0 using sc1
_M.sc_inc_gpc0(txn, "st_cache", 1)
```

---

### _M.sc_inc_gpc1

Increments gpc1 counter for the specified stick-table using configurable track-sc index.

**Signature:**
```lua
_M.sc_inc_gpc1(txn, backend, sc_index)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `txn` | transaction | HAProxy transaction object |
| `backend` | string | Backend name with stick-table |
| `sc_index` | number | Track-sc index (0, 1, or 2) |

---

## Module Properties

### _M.version

Current module version string.

**Type:** string

**Example:**
```lua
print(_M.version)  -- "0.4.0"
```

---

## Dependencies

The module requires the following Lua libraries:

| Library | Purpose |
|---------|---------|
| `utils` | IP address utilities ([haproxy-lua-utils](https://github.com/dobrevit/haproxy-lua-utils)) |
| `socket` | DNS resolution |
| `inspect` | Debug output formatting |
