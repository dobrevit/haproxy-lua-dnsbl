# Architecture Overview

This document explains how the HAProxy Lua DNSBL module works, including the request flow, caching mechanism, and component interactions.

## High-Level Architecture

```
                                    ┌─────────────────────────────────────────┐
                                    │              HAProxy                    │
                                    │                                         │
   ┌──────────┐                     │  ┌────────────────────────────────────┐ │
   │  Client  │ ─── HTTP Request ──►│  │         Frontend                   │ │
   │          │                     │  │                                    │ │
   └──────────┘                     │  │  http-request lua.dnsbl_query      │ │
        ▲                           │  │  http-request lua.dnsbl_block      │ │
        │                           │  └─────────────┬──────────────────────┘ │
        │                           │                │                        │
        │                           │                ▼                        │
        │                           │  ┌────────────────────────────────────┐ │
        │                           │  │         dnsbl.lua                  │ │
        │                           │  │                                    │ │
        │                           │  │  1. Get client IP                  │ │
        │                           │  │  2. Check stick-table cache        │ │
        │                           │  │  3. DNS lookup (if needed)         │ │
        │                           │  │  4. Update cache                   │ │
        │                           │  │  5. Set response headers           │ │
        │                           │  │  6. Block or allow                 │ │
        │                           │  └──────┬───────────────┬─────────────┘ │
        │                           │         │               │               │
        │                           │         ▼               ▼               │
        │                           │  ┌────────────┐  ┌─────────────────┐    │
        │                           │  │ Stick-Table│  │  DNS Resolver   │    │
        │                           │  │   Cache    │  │                 │    │
        │                           │  │            │  │ DNSBL Query:    │    │
        │                           │  │ gpc0=allow │  │ 1.2.0.192.      │    │
        │                           │  │ gpc1=deny  │  │ torexit.dan.    │    │
        │                           │  │            │  │ me.uk           │    │
        │                           │  └────────────┘  └────────┬────────┘    │
        │                           │                           │             │
        │                           └───────────────────────────┼─────────────┘
        │                                                       │
        │  401 Unauthorized                                     ▼
        │  (if blocked)                                  ┌─────────────┐
        └────────────────────────────────────────────────│   DNSBL     │
                                                         │   Server    │
                                                         └─────────────┘
```

## Components

### 1. dnsbl.lua Module

The core Lua module that provides two HAProxy actions:

| Action | Purpose |
|--------|---------|
| `lua.dnsbl_query` | Performs the DNSBL lookup and caches the result |
| `lua.dnsbl_block` | Blocks the request if the IP is blacklisted |

### 2. Stick-Table Cache

HAProxy stick-tables are used to cache DNSBL lookup results, avoiding repeated DNS queries for the same IP address.

```
┌────────────────────────────────────────────────────────────┐
│                     Stick-Table Entry                      │
├──────────────┬──────────────┬──────────────┬───────────────┤
│     Key      │    gpc0      │    gpc1      │   Expiry      │
│   (IP addr)  │  (allowed)   │  (blocked)   │   (TTL)       │
├──────────────┼──────────────┼──────────────┼───────────────┤
│ 192.0.2.1    │      1       │      0       │  30 minutes   │
│ 198.51.100.1 │      0       │      1       │  30 minutes   │
└──────────────┴──────────────┴──────────────┴───────────────┘
```

**Counter meanings:**
- `gpc0 = 1` → IP was checked and **allowed** (not in blacklist)
- `gpc1 = 1` → IP was checked and **blocked** (found in blacklist)
- Both `0` → IP not yet checked (new visitor)

### 3. DNS Resolution

The module uses Lua's `socket.dns` library to perform DNS queries.

**Query format:**
```
{reversed_ip}.{dnsbl_domain}

Example:
  Client IP: 192.0.2.100
  Reversed:  100.2.0.192
  Query:     100.2.0.192.torexit.dan.me.uk
```

## Request Flow

### Flow 1: New Visitor (Cache Miss)

```
┌──────┐     ┌─────────┐     ┌───────────┐     ┌──────────┐     ┌────────┐
│Client│     │ HAProxy │     │ dnsbl.lua │     │Stick-Tbl │     │  DNSBL │
└──┬───┘     └────┬────┘     └─────┬─────┘     └────┬─────┘     └───┬────┘
   │              │                │                │               │
   │ HTTP Request │                │                │               │
   │─────────────►│                │                │               │
   │              │ dnsbl_query()  │                │               │
   │              │───────────────►│                │               │
   │              │                │ lookup(IP)     │               │
   │              │                │───────────────►│               │
   │              │                │ gpc0=0,gpc1=0  │               │
   │              │                │◄───────────────│               │
   │              │                │                │               │
   │              │                │ DNS query      │               │
   │              │                │───────────────────────────────►│
   │              │                │                │   NXDOMAIN    │
   │              │                │◄───────────────────────────────│
   │              │                │                │               │
   │              │                │ inc_gpc0()     │               │
   │              │                │───────────────►│               │
   │              │                │                │               │
   │              │ Set headers    │                │               │
   │              │◄───────────────│                │               │
   │              │                │                │               │
   │   200 OK     │                │                │               │
   │◄─────────────│                │                │               │
```

### Flow 2: Returning Visitor (Cache Hit - Allowed)

```
┌──────┐     ┌─────────┐     ┌───────────┐     ┌──────────┐
│Client│     │ HAProxy │     │ dnsbl.lua │     │Stick-Tbl │
└──┬───┘     └────┬────┘     └─────┬─────┘     └────┬─────┘
   │              │                │                │
   │ HTTP Request │                │                │
   │─────────────►│                │                │
   │              │ dnsbl_query()  │                │
   │              │───────────────►│                │
   │              │                │ lookup(IP)     │
   │              │                │───────────────►│
   │              │                │ gpc0=1         │  ◄── Cache hit!
   │              │                │◄───────────────│
   │              │                │                │
   │              │ Headers: CACHE-ALLOW            │
   │              │◄───────────────│                │
   │              │                │                │
   │   200 OK     │                │     (No DNS query needed)
   │◄─────────────│                │
```

### Flow 3: Blocked Visitor

```
┌──────┐     ┌─────────┐     ┌───────────┐     ┌──────────┐
│Client│     │ HAProxy │     │ dnsbl.lua │     │Stick-Tbl │
└──┬───┘     └────┬────┘     └─────┬─────┘     └────┬─────┘
   │              │                │                │
   │ HTTP Request │                │                │
   │─────────────►│                │                │
   │              │ dnsbl_query()  │                │
   │              │───────────────►│                │
   │              │                │ lookup(IP)     │
   │              │                │───────────────►│
   │              │                │ gpc1=1         │  ◄── Blacklisted!
   │              │                │◄───────────────│
   │              │ Headers: CACHE-DENY             │
   │              │◄───────────────│                │
   │              │                │                │
   │              │ dnsbl_block()  │                │
   │              │───────────────►│                │
   │              │ 401 reply      │                │
   │              │◄───────────────│                │
   │              │                │                │
   │ 401 Unauth.  │                │                │
   │◄─────────────│                │
```

## Caching Strategy

### Why Cache?

1. **Performance** - DNS queries add latency (typically 10-100ms)
2. **Rate limiting** - Some DNSBLs limit query frequency
3. **Reliability** - Cached results available even if DNSBL is down

### Cache Parameters

| Parameter | Configuration | Purpose |
|-----------|--------------|---------|
| TTL | `expire` in stick-table | How long to cache results |
| Size | `size` in stick-table | Maximum number of cached IPs |
| Type | `type ipv6` | Stick-table key type |

### Recommended Settings

```haproxy
backend st_dnsbl_cache
    stick-table type ipv6 size 1m expire 30m store gpc0,gpc1
```

- **size 1m** - Store up to 1 million IP addresses
- **expire 30m** - Cache results for 30 minutes
- **type ipv6** - Supports both IPv4 and IPv6 (IPv4 mapped to ::ffff:x.x.x.x)

## IPv6 Support

The module handles IPv4-mapped IPv6 addresses automatically:

```
IPv4 address: 192.0.2.1
IPv6 mapped:  ::ffff:192.0.2.1
```

This ensures consistent stick-table lookups regardless of whether HAProxy sees the original IPv4 or the mapped IPv6 format.

## Error Handling

| Scenario | Behavior |
|----------|----------|
| DNS timeout | Request allowed, header set to `DNSBL-ERROR-ALLOW` |
| Stick-table missing | Debug message logged, request allowed |
| Invalid IP format | Debug message logged, request blocked |
| DNSBL unreachable | Request allowed (fail-open) |

The module follows a **fail-open** policy - if there's an error checking the blacklist, the request is allowed through. This prevents a DNSBL outage from blocking all traffic.

## Performance Considerations

1. **First request per IP** - Adds DNS query latency (~10-100ms)
2. **Cached requests** - Minimal overhead (stick-table lookup)
3. **Memory usage** - ~200 bytes per cached IP address

### Tuning Tips

- Increase stick-table `expire` time for lower DNS query volume
- Increase stick-table `size` for high-traffic sites with many unique visitors
- Use local DNS resolver for faster DNSBL queries
