# Understanding DNSBL (DNS Blacklists)

This guide explains how DNS-based blacklists work and how this module uses them to protect your web applications.

## What is a DNSBL?

A **DNSBL** (DNS-based Blackhole List) is a method for publishing a list of IP addresses using the Internet's Domain Name System. These lists typically contain:

- IP addresses of known spam sources
- Tor exit nodes
- Compromised machines (botnets)
- Open proxies
- Known malicious actors

### How DNSBL Queries Work

DNSBL uses a clever trick: it encodes IP addresses into DNS hostnames. The process works like this:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DNSBL Query Process                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Client IP: 192.0.2.100                                             │
│                                                                     │
│  Step 1: Reverse the IP octets                                      │
│          192.0.2.100  →  100.2.0.192                                │
│                                                                     │
│  Step 2: Append the DNSBL domain                                    │
│          100.2.0.192 + .torexit.dan.me.uk                           │
│                       = 100.2.0.192.torexit.dan.me.uk               │
│                                                                     │
│  Step 3: Perform DNS A record lookup                                │
│          Query: 100.2.0.192.torexit.dan.me.uk                       │
│                                                                     │
│  Step 4: Interpret the response                                     │
│          - NXDOMAIN (not found) → IP is NOT blacklisted             │
│          - A record response    → IP IS blacklisted                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Why Reverse the IP?

Reversing the IP address allows DNS servers to efficiently index and search for IP ranges. This is the same technique used in reverse DNS (PTR records) and leverages DNS's hierarchical structure.

---

## Interpreting Responses

### NXDOMAIN Response

If the DNS query returns `NXDOMAIN` (Non-Existent Domain), it means:

- The IP address is **NOT** in the blacklist
- The request should be **ALLOWED**

### IP Address Response

If the DNS query returns an IP address (typically in the `127.0.0.x` range), it means:

- The IP address **IS** in the blacklist
- The request should be **BLOCKED**

Different response codes can indicate different reasons for blocking:

```
Response: 127.0.0.100  →  Tor exit node (dan.me.uk)
Response: 127.0.0.2    →  Tor exit node (torproject.org)
Response: 127.0.0.4    →  Known exploit source (Spamhaus XBL)
```

---

## Supported DNSBL Providers

### 1. Dan.me.uk Tor Exit List

**Domain:** `.torexit.dan.me.uk`

| Response | Meaning |
|----------|---------|
| `127.0.0.100` | IP is a Tor exit node |
| `NXDOMAIN` | IP is not a Tor exit node |

**Use case:** Block or flag Tor exit nodes.

**Example query:**
```
IP: 185.220.101.1 (example Tor exit)
Query: 1.101.220.185.torexit.dan.me.uk
```

### 2. Tor Project Exit List

**Domain:** `.exitlist.torproject.org`

The official Tor Project maintains this list. Query format includes the destination port:

| Response | Meaning |
|----------|---------|
| `127.0.0.2` | IP is a Tor exit node |
| `NXDOMAIN` | IP is not a Tor exit node |

**Note:** The Tor Project list has specific query formatting requirements.

### 3. Spamhaus Lists

Spamhaus operates several blacklists, each with specific response codes:

#### XBL (Exploits Block List)

**Domain:** `xbl.spamhaus.org`

Lists IP addresses of hijacked PCs infected with illegal third-party exploits.

| Response | Zone | Description |
|----------|------|-------------|
| `127.0.0.4` | XBL | CBL Data (Composite Blocking List) |

#### SBL (Spamhaus Block List)

**Domain:** `sbl.spamhaus.org`

Lists IP addresses from which Spamhaus has seen spam being sent.

| Response | Zone | Description |
|----------|------|-------------|
| `127.0.0.2` | SBL | Spamhaus SBL Data |
| `127.0.0.3` | SBL | Spamhaus SBL CSS Data |
| `127.0.0.9` | SBL | Spamhaus DROP/EDROP Data |

#### PBL (Policy Block List)

**Domain:** `pbl.spamhaus.org`

Lists IP ranges that should not be sending unauthenticated SMTP email.

| Response | Zone | Description |
|----------|------|-------------|
| `127.0.0.10` | PBL | ISP Maintained |
| `127.0.0.11` | PBL | Spamhaus Maintained |

#### ZEN (Combined)

**Domain:** `zen.spamhaus.org`

Combines all Spamhaus lists (SBL + XBL + PBL) in a single query.

#### Error Responses

Spamhaus returns special codes for query errors:

| Response | Meaning |
|----------|---------|
| `127.255.255.252` | Typing error in DNSBL name |
| `127.255.255.254` | Query via public/open resolver (blocked) |
| `127.255.255.255` | Excessive number of queries (rate limited) |

**Important:** Spamhaus limits queries from public DNS resolvers. For production use, you should:
1. Use your own recursive DNS resolver
2. Register for a free data feed (for high-volume use)

---

## Use Cases

### 1. Blocking Tor Exit Nodes

Tor provides anonymity, but some sites need to block it:

```
Legitimate reasons to block:
- Prevent abuse from anonymous sources
- Regulatory compliance
- Reduce fraud from anonymous actors

Considerations:
- You also block legitimate privacy-conscious users
- Consider CAPTCHAs or rate limiting instead of blocking
```

### 2. Blocking Known Spam Sources

Using Spamhaus to block known spam sources:

```
Benefits:
- Block IPs with known spam history
- Reduce comment spam, form abuse
- Lower bot traffic

Considerations:
- False positives are possible
- IP reputations can lag behind ownership changes
```

### 3. Blocking Compromised Machines

The XBL lists machines infected with malware:

```
Benefits:
- Block botnets
- Reduce DDoS traffic
- Prevent credential stuffing

Considerations:
- Legitimate users with infected machines get blocked
- Provide clear error messages so they know to scan their computer
```

---

## Best Practices

### 1. Cache Results

DNSBL queries add latency. Always use stick-table caching:

```haproxy
# Cache for 30 minutes
backend st_cache
    stick-table type ipv6 size 1m expire 30m store gpc0,gpc1
```

### 2. Fail Open

If the DNSBL is unreachable, allow traffic rather than block:

```
DNSBL down + fail-closed = All traffic blocked = Outage
DNSBL down + fail-open   = All traffic allowed = Acceptable risk
```

This module implements fail-open behavior by default.

### 3. Log DNSBL Decisions

Always log which IPs were blocked and why:

```haproxy
log-format "... dnsbl:%[req.hdr(X-DNSBL-Action)]"
```

### 4. Provide Clear Error Messages

When blocking a user, tell them why:

```
401 Unauthorized
Denial-Reason: Your IP address is listed in a DNS blacklist
```

### 5. Use Multiple Lists Carefully

More lists = more false positives:

```
Tor list alone: Low false positive risk
XBL alone: Low false positive risk
PBL: Higher false positive risk (residential IPs)
All combined: Highest false positive risk
```

### 6. Monitor False Positives

Regularly review blocked requests:

```bash
# Find blocked requests in logs
grep "DNSBL-.*-DENY" /var/log/haproxy.log | awk '{print $6}' | sort | uniq -c
```

---

## Technical Details

### DNS Query Performance

| Location | Typical Latency |
|----------|-----------------|
| Local DNS cache | < 1ms |
| Local recursive resolver | 1-10ms |
| ISP DNS resolver | 10-50ms |
| DNSBL server (first query) | 50-200ms |

### IPv6 Considerations

DNSBL queries for IPv6 are more complex:

```
IPv4: 192.0.2.1 → 1.2.0.192.dnsbl.example.com
IPv6: 2001:db8::1 → 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.dnsbl.example.com
```

Most DNSBLs only support IPv4 queries. The Tor lists, for example, only list IPv4 exit nodes.

### Rate Limiting

Most DNSBLs rate limit queries:

| Provider | Free Limit | Notes |
|----------|------------|-------|
| dan.me.uk | Reasonable | No strict limit published |
| Spamhaus | ~300k/day | Commercial license for more |
| torproject.org | Reasonable | Rate limits apply |

For high-volume use, consider:
1. Caching with long TTL
2. Commercial data feeds
3. Self-hosted mirrors (where available)

---

## Security Considerations

### DNSBL Poisoning

A malicious actor could potentially:
- Intercept DNS responses
- Return false positives (block legitimate users)
- Return false negatives (allow malicious users)

Mitigation:
- Use DNSSEC where available
- Use trusted, local DNS resolvers
- Don't rely solely on DNSBL for security

### Privacy

DNSBL queries reveal which IPs are accessing your service to the DNSBL operator. Consider:
- Running local DNSBL mirrors for sensitive applications
- The privacy trade-off vs. security benefits
