# HAProxy Lua DNSBL Documentation

Welcome to the HAProxy Lua DNSBL documentation. This module enables dynamic request blocking based on DNS blacklist lookups directly within HAProxy.

## Quick Start

1. [Installation & Configuration](configuration.md) - Get up and running quickly
2. [Basic Example](../examples/basic/haproxy.cfg) - Minimal working configuration

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture Overview](architecture.md) | How the module works, request flow, and caching mechanism |
| [API Reference](api-reference.md) | Complete function documentation with parameters and examples |
| [Configuration Guide](configuration.md) | HAProxy setup, stick-tables, and module loading |
| [Understanding DNSBL](dnsbl-explained.md) | How DNS blacklists work and supported providers |
| [HTTP Headers Reference](http-headers.md) | All headers set by the module |
| [Troubleshooting](troubleshooting.md) | Common issues and debugging tips |

## Examples

| Example | Description |
|---------|-------------|
| [Basic Setup](../examples/basic/) | Minimal configuration using direct client IP |
| [Behind Proxy](../examples/behind-proxy/) | Using X-Forwarded-For when behind a reverse proxy |
| [Multiple DNSBLs](../examples/multi-dnsbl/) | Querying multiple blacklist providers |
| [Docker Environment](../examples/docker/) | Complete Docker-based test environment |
| [Logging](../examples/logging/) | Custom log formats with DNSBL headers |

## Supported DNSBL Providers

| Provider | Domain | Response Code | Description |
|----------|--------|---------------|-------------|
| Dan.me.uk Tor Exit | `.torexit.dan.me.uk` | `127.0.0.100` | Tor exit node list |
| Tor Project Exit List | `.exitlist.torproject.org` | `127.0.0.2` | Official Tor exit list |
| Spamhaus XBL | `xbl.spamhaus.org` | Various | Exploits Block List |
| Spamhaus ZEN | `zen.spamhaus.org` | Various | Combined Spamhaus list |

## Version

Current version: **0.4.0**

## License

MIT License - See [LICENSE](../LICENSE) for details.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/dobrevit/haproxy-lua-dnsbl/issues.
