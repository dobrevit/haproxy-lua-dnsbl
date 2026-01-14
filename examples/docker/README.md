# Docker DNSBL Example

A complete Docker-based test environment for HAProxy Lua DNSBL.

## Quick Start

```bash
# Build and start
docker-compose up -d

# Test
curl http://localhost:8080/

# Check DNSBL headers
curl -v http://localhost:8080/ 2>&1 | grep X-DNSBL

# View logs
docker-compose logs -f haproxy

# Stop
docker-compose down
```

## Components

| Service | Port | Description |
|---------|------|-------------|
| haproxy | 8080 | HAProxy with DNSBL module |
| backend | 80 | Simple nginx backend |

## Testing DNSBL

### Test with a spoofed IP (simulating proxy)

```bash
# Test with a non-Tor IP
curl -H "X-Forwarded-For: 1.2.3.4" http://localhost:8080/

# Test with a Tor exit IP (get current from torproject.org)
curl -H "X-Forwarded-For: 185.220.101.1" http://localhost:8080/
```

### Check stick-table

```bash
# View cached entries
docker exec haproxy-dnsbl echo "show table st_dnsbl_cache" | socat stdio /var/run/haproxy/admin.sock

# Clear cache
docker exec haproxy-dnsbl echo "clear table st_dnsbl_cache" | socat stdio /var/run/haproxy/admin.sock
```

## File Structure

```
docker/
├── docker-compose.yml      # Docker Compose configuration
├── haproxy/
│   ├── Dockerfile          # HAProxy with Lua modules
│   └── haproxy.cfg         # HAProxy configuration
└── README.md               # This file
```

## Building

```bash
# Rebuild after changes
docker-compose build --no-cache

# Or build just haproxy
docker-compose build haproxy
```

## Customization

### Change DNSBL provider

Edit `haproxy/haproxy.cfg`:

```haproxy
# For Spamhaus instead of Tor list
http-request lua.dnsbl_query st_dnsbl_cache xbl.spamhaus.org "" X-Forwarded-For
```

### Use different Lua modules

Add to `haproxy/Dockerfile`:

```dockerfile
RUN wget -O /usr/share/lua/5.3/mymodule.lua https://example.com/mymodule.lua
```

## Troubleshooting

### DNS not working inside container

Check DNS configuration:

```bash
docker exec haproxy-dnsbl cat /etc/resolv.conf
docker exec haproxy-dnsbl dig google.com
```

### Lua module errors

Check HAProxy logs:

```bash
docker-compose logs haproxy | grep -i lua
```

### Permission issues

Ensure files have correct permissions:

```bash
chmod 644 haproxy/haproxy.cfg
```
