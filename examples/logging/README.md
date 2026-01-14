# DNSBL Logging Examples

This example demonstrates various logging configurations for monitoring DNSBL activity.

## Log Format Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `%[req.hdr(X-DNSBL-Action)]` | Lookup result | `DNSBL-LOOKUP-ALLOW` |
| `%[req.hdr(X-DNSBL-Is-Allowed)]` | Boolean | `1` or `0` |
| `%[req.hdr(X-DNSBL-Client-IP)]` | Checked IP | `192.0.2.100` |
| `%[req.hdr(X-DNSBL-Query)]` | DNS query | `100.2.0.192.torexit.dan.me.uk` |
| `%[req.hdr(X-DNSBL-Version)]` | Module version | `0.4.0` |

## Example Log Outputs

### Standard Format
```
192.0.2.1:54321 [14/Jan/2024:12:00:00.000] http-in webservers/web1 ... dnsbl_action:DNSBL-LOOKUP-ALLOW dnsbl_ip:192.0.2.1 dnsbl_allowed:1
```

### JSON Format
```json
{
  "timestamp": "14/Jan/2024:12:00:00.000",
  "client_ip": "192.0.2.1",
  "dnsbl": {
    "action": "DNSBL-LOOKUP-DENY",
    "client_ip": "185.220.101.1",
    "allowed": "0"
  }
}
```

### Minimal Format
```
[14/Jan/2024:12:00:00.000] 185.220.101.1 DNSBL-LOOKUP-DENY GET / HTTP/1.1
```

## Log Analysis Commands

### Count DNSBL actions
```bash
grep -oP 'dnsbl_action:\K[^ ]+' /var/log/haproxy.log | sort | uniq -c | sort -rn
```

### Find blocked IPs
```bash
grep 'DENY' /var/log/haproxy.log | grep -oP 'dnsbl_ip:\K[^ ]+' | sort | uniq -c | sort -rn
```

### Cache hit ratio
```bash
awk '/dnsbl_action:DNSBL-CACHE/ {cache++} /dnsbl_action:DNSBL-LOOKUP/ {lookup++} END {print "Cache:", cache, "Lookup:", lookup, "Hit%:", cache/(cache+lookup)*100}' /var/log/haproxy.log
```

## Monitoring

### Prometheus/Grafana
Use HAProxy's built-in stats with DNSBL log parsing:

```bash
# Example: count blocked requests per minute
grep 'DNSBL-.*-DENY' /var/log/haproxy.log | \
  awk '{print substr($0, 1, 20)}' | \
  uniq -c
```

### Alerting
Alert on high block rates:

```bash
# Alert if > 100 blocks in last 5 minutes
COUNT=$(grep -c 'DENY' /var/log/haproxy.log)
if [ $COUNT -gt 100 ]; then
  echo "High DNSBL block rate: $COUNT"
fi
```
