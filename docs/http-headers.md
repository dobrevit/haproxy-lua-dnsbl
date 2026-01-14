# HTTP Headers Reference

The HAProxy Lua DNSBL module sets several HTTP headers on each request. These headers can be used for:

- Logging and analytics
- Downstream decision making
- Debugging
- Monitoring and alerting

## Headers Set by dnsbl_query

### X-DNSBL-Action

**Description:** Indicates the result of the DNSBL lookup or cache check.

**Type:** String

**Possible Values:**

| Value | Description |
|-------|-------------|
| `DNSBL-CACHE-ALLOW` | IP found in cache, previously determined to be allowed |
| `DNSBL-CACHE-DENY` | IP found in cache, previously determined to be blocked |
| `DNSBL-LOOKUP-ALLOW` | Fresh DNS lookup performed, IP not in blacklist |
| `DNSBL-LOOKUP-DENY` | Fresh DNS lookup performed, IP found in blacklist |
| `DNSBL-ERROR-ALLOW` | Error during lookup, defaulting to allow (fail-open) |

**Example:**
```http
X-DNSBL-Action: DNSBL-LOOKUP-ALLOW
```

**Usage in HAProxy ACL:**
```haproxy
acl dnsbl_blocked req.hdr(X-DNSBL-Action) -m sub DENY
http-request deny if dnsbl_blocked
```

---

### X-DNSBL-Is-Allowed

**Description:** Boolean indicator of whether the request is allowed.

**Type:** Integer (0 or 1)

**Values:**

| Value | Meaning |
|-------|---------|
| `1` | Request is allowed |
| `0` | Request is blocked |

**Example:**
```http
X-DNSBL-Is-Allowed: 1
```

**Usage in HAProxy ACL:**
```haproxy
acl dnsbl_allowed req.hdr(X-DNSBL-Is-Allowed) -m str 1
http-request deny unless dnsbl_allowed
```

---

### X-DNSBL-Version

**Description:** Version of the DNSBL module that processed the request.

**Type:** String (semantic version)

**Example:**
```http
X-DNSBL-Version: 0.4.0
```

**Use case:** Helpful for debugging and ensuring all HAProxy nodes run the same version.

---

### X-DNSBL-Client-IP

**Description:** The client IP address that was checked against the DNSBL.

**Type:** String (IP address)

**Example:**
```http
X-DNSBL-Client-IP: 192.0.2.100
```

**Notes:**
- This reflects the actual IP used for the lookup
- May differ from the connection source if `src_header` or `src_var` was used
- Useful for verifying correct IP extraction when behind proxies

---

### X-DNSBL-Query

**Description:** The full DNS query string that was used for the lookup.

**Type:** String (DNS hostname)

**Example:**
```http
X-DNSBL-Query: 100.2.0.192.torexit.dan.me.uk
```

**Notes:**
- Format is `{reversed_ip}.{dnsbl_domain}`
- Useful for debugging DNS resolution issues
- Can be used to manually verify lookups with `dig` or `nslookup`

---

### X-DNSBL-Error

**Description:** Error message when the lookup fails. Only set when an error occurs.

**Type:** String

**Example:**
```http
X-DNSBL-Error: No entry found
```

**Possible Values:**
- `No entry found` - IP not in stick-table (shouldn't happen normally)
- `Unsupported stick-table type` - Stick-table type not supported
- DNS resolution errors

---

### X-DNSBL-Zone (Spamhaus only)

**Description:** The Spamhaus zone that matched. Only set for Spamhaus lookups.

**Type:** String

**Possible Values:**

| Value | Full Name |
|-------|-----------|
| `SBL` | Spamhaus Block List |
| `XBL` | Exploits Block List |
| `PBL` | Policy Block List |
| `Any` | Error condition |

**Example:**
```http
X-DNSBL-Zone: XBL
```

---

### X-DNSBL-Description (Spamhaus only)

**Description:** Human-readable description of why the IP was blocked. Only set for Spamhaus lookups.

**Type:** String

**Example:**
```http
X-DNSBL-Description: CBL Data
```

**Possible Values:**
- `Spamhaus SBL Data`
- `Spamhaus SBL CSS Data`
- `CBL Data`
- `Spamhaus DROP/EDROP Data`
- `ISP Maintained`
- `Spamhaus Maintained`
- `Typing error in DNSBL name`
- `Query via public/open resolver`
- `Excessive number of queries`

---

## Headers Set by dnsbl_block

### Denial-Reason

**Description:** Explanation of why the request was blocked. Only included in 401 response.

**Type:** String

**Example:**
```http
Denial-Reason: DNSBL: IP found in hard banlist. BLOCK request
```

### Server

**Description:** Server identification in the 401 response.

**Type:** String

**Example:**
```http
Server: DNSBL/0.4.0
```

---

## Using Headers in HAProxy Configuration

### Logging Headers

```haproxy
# Custom log format including DNSBL headers
log-format "%ci:%cp [%tr] %ft %b/%s %ST %B %{+Q}r dnsbl:%[req.hdr(X-DNSBL-Action)] ip:%[req.hdr(X-DNSBL-Client-IP)]"
```

### Conditional Routing Based on Headers

```haproxy
frontend http-in
    bind *:80

    # Route blocked users to a different backend (e.g., CAPTCHA)
    acl is_dnsbl_deny req.hdr(X-DNSBL-Action) -m sub DENY
    use_backend captcha_servers if is_dnsbl_deny

    default_backend normal_servers
```

### Removing Headers Before Backend

```haproxy
# Remove DNSBL headers before passing to backend
http-request del-header X-DNSBL-Action
http-request del-header X-DNSBL-Is-Allowed
http-request del-header X-DNSBL-Version
http-request del-header X-DNSBL-Client-IP
http-request del-header X-DNSBL-Query
http-request del-header X-DNSBL-Error
http-request del-header X-DNSBL-Zone
http-request del-header X-DNSBL-Description
```

### Passing Headers to Backend for Processing

```haproxy
# Keep headers for backend processing (e.g., additional logging)
# No action needed - headers are forwarded by default

# Backend application can access:
# - X-DNSBL-Action to know the lookup result
# - X-DNSBL-Client-IP for logging the actual client IP
```

---

## Header Summary Table

| Header | Always Set | Type | Purpose |
|--------|------------|------|---------|
| `X-DNSBL-Action` | Yes | String | Lookup result |
| `X-DNSBL-Is-Allowed` | Yes | Integer | Allow/block indicator |
| `X-DNSBL-Version` | Yes | String | Module version |
| `X-DNSBL-Client-IP` | Yes | String | IP that was checked |
| `X-DNSBL-Query` | Yes | String | DNS query string |
| `X-DNSBL-Error` | On error | String | Error description |
| `X-DNSBL-Zone` | Spamhaus | String | Spamhaus zone |
| `X-DNSBL-Description` | Spamhaus | String | Block reason |
| `Denial-Reason` | On block | String | User-facing reason |
| `Server` | On block | String | Server identification |

---

## Security Considerations

### Header Injection

The module sets headers based on:
- IP addresses (validated format)
- DNSBL domain (from configuration)
- DNS responses (127.x.x.x range)

These values are controlled and not subject to header injection.

### Information Disclosure

Headers like `X-DNSBL-Action` reveal security decisions. Consider:

```haproxy
# Remove sensitive headers from response to client
http-response del-header X-DNSBL-Action
http-response del-header X-DNSBL-Query
```

Or only forward them to the backend:

```haproxy
# Headers are request headers, not automatically in response
# Only explicit add_header in Lua adds them to response
```

### Client Spoofing

A malicious client cannot spoof these headers because:
1. They are set by the Lua module after processing
2. HAProxy `req_set_header` overwrites any existing value
3. The headers are set based on actual lookup results
