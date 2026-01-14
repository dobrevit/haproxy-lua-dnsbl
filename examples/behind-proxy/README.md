# Behind Proxy DNSBL Example

When HAProxy is behind another reverse proxy (nginx, CDN, load balancer), you need to extract the real client IP from an HTTP header.

## Common Headers

| Proxy Type | Header |
|------------|--------|
| Most proxies | `X-Forwarded-For` |
| nginx (when configured) | `X-Real-IP` |
| Cloudflare | `CF-Connecting-IP` |
| AWS ALB | `X-Forwarded-For` |
| Akamai | `True-Client-IP` |

## Configuration Examples

### Simple X-Forwarded-For

```haproxy
http-request track-sc0 hdr(X-Forwarded-For) table st_dnsbl_cache
http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk "" X-Forwarded-For
```

### Multiple Proxies (X-Forwarded-For: client, proxy1, proxy2)

```haproxy
# Extract first IP only
http-request set-var(txn.real_ip) hdr(X-Forwarded-For),word(1,",")
http-request track-sc0 var(txn.real_ip) table st_dnsbl_cache
http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk txn.real_ip ""
```

### Cloudflare

```haproxy
http-request track-sc0 hdr(CF-Connecting-IP) table st_dnsbl_cache
http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk "" CF-Connecting-IP
```

## Testing

```bash
# Simulate request from behind proxy
curl -H "X-Forwarded-For: 192.0.2.100" http://localhost/

# Check which IP was used
curl -s -D - -H "X-Forwarded-For: 192.0.2.100" http://localhost/ -o /dev/null | grep X-DNSBL-Client-IP
# Should show: X-DNSBL-Client-IP: 192.0.2.100
```

## Security Considerations

**Warning:** When using headers for client IP, ensure:

1. Only trusted proxies can reach HAProxy directly
2. Proxies are configured to set/overwrite the header (not append)
3. Consider validating the header format

```haproxy
# Only trust internal proxy IPs
acl is_trusted_proxy src 10.0.0.0/8 192.168.0.0/16

# Reject requests that claim to be forwarded but aren't from trusted proxies
http-request deny if !is_trusted_proxy { req.hdr(X-Forwarded-For) -m found }
```
