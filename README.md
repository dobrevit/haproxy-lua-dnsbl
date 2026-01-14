# haproxy-lua-dnsbl

DNSBL (DNS blacklisting) module for HAProxy Lua. Dynamically block requests based on the response of the DNS query or use any of the added extra request headers to make decisions down the line.

## Features

- Query multiple DNSBL providers (Tor exit lists, Spamhaus, etc.)
- Cache results using HAProxy stick-tables for optimal performance
- Configurable track-sc index (sc0, sc1, sc2) for flexible stick-table usage
- Detailed HTTP headers for logging and downstream processing
- Fail-open design - errors don't block legitimate traffic

## Supported DNSBL Providers

| Provider | Domain | Description |
|----------|--------|-------------|
| Dan.me.uk Tor List | `.torexit.dan.me.uk` | Tor exit node list |
| Tor Project | `.exitlist.torproject.org` | Official Tor exit list |
| Spamhaus SBL | `sbl.spamhaus.org` | Spam sources |
| Spamhaus XBL | `xbl.spamhaus.org` | Exploits/botnets |
| Spamhaus PBL | `pbl.spamhaus.org` | Policy block list |
| Spamhaus ZEN | `zen.spamhaus.org` | Combined list |

## Quick Start

```haproxy
global
    lua-load /usr/share/lua/5.3/dnsbl.lua

backend st_dnsbl_cache
    stick-table type ipv6 size 1m expire 30m store gpc0,gpc1

frontend http-in
    bind *:80
    http-request track-sc0 src table st_dnsbl_cache
    http-request lua.dnsbl_query st_dnsbl_cache .torexit.dan.me.uk "" ""
    http-request lua.dnsbl_block st_dnsbl_cache
    default_backend servers
```

## Installation

`haproxy-lua-dnsbl` depends on [utils](https://github.com/dobrevit/haproxy-lua-utils) and `socket` library. Download copies to your Lua path:

```bash
# Install to Lua path (e.g., /usr/share/lua/5.3/)
cp src/dnsbl.lua /usr/share/lua/5.3/

# Install dependencies
wget -O /usr/share/lua/5.3/utils.lua \
  https://raw.githubusercontent.com/dobrevit/haproxy-lua-utils/main/src/utils.lua
```

## Documentation

Full documentation is available in the [docs](./docs/) folder:

- [Documentation Index](./docs/README.md)
- [Architecture Overview](./docs/architecture.md) - How the module works
- [API Reference](./docs/api-reference.md) - Complete function documentation
- [Configuration Guide](./docs/configuration.md) - HAProxy setup instructions
- [Understanding DNSBL](./docs/dnsbl-explained.md) - How DNS blacklists work
- [HTTP Headers Reference](./docs/http-headers.md) - Headers set by the module
- [Troubleshooting](./docs/troubleshooting.md) - Common issues and solutions

## Examples

The [examples](./examples/) folder contains ready-to-use configurations:

| Example | Description |
|---------|-------------|
| [Basic](./examples/basic/) | Minimal working configuration |
| [Behind Proxy](./examples/behind-proxy/) | Using X-Forwarded-For header |
| [Multiple DNSBLs](./examples/multi-dnsbl/) | Querying multiple providers |
| [Docker](./examples/docker/) | Complete Docker test environment |
| [Logging](./examples/logging/) | Custom log formats with DNSBL headers |

## Usage

### Basic Usage

```haproxy
http-request lua.dnsbl_query <backend> <domain> <src_var> <src_header> [sc_index]
http-request lua.dnsbl_block <backend>
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `backend` | Backend name containing the stick-table |
| `domain` | DNSBL domain (e.g., `.torexit.dan.me.uk`) |
| `src_var` | HAProxy variable with client IP (optional) |
| `src_header` | HTTP header with client IP (optional) |
| `sc_index` | Track-sc index: 0, 1, or 2 (optional, default: 0) |

### Examples

```haproxy
# Basic - direct client IP
http-request lua.dnsbl_query st_cache .torexit.dan.me.uk "" ""

# Behind proxy - use X-Forwarded-For
http-request lua.dnsbl_query st_cache .torexit.dan.me.uk "" X-Forwarded-For

# Use sc1 instead of sc0
http-request lua.dnsbl_query st_cache .torexit.dan.me.uk "" "" 1

# Multiple providers with different track-sc indices
http-request track-sc0 src table st_tor
http-request track-sc1 src table st_spam
http-request lua.dnsbl_query st_tor .torexit.dan.me.uk "" "" 0
http-request lua.dnsbl_query st_spam xbl.spamhaus.org "" "" 1
```

## How it Works

The library uses the `socket.dns` class to make DNS queries. The DNSBL domain is expected to return:

- **NXDOMAIN** - IP is not blacklisted (request allowed)
- **A record response** - IP is blacklisted (request blocked)

Results are cached using HAProxy's stick-table with `gpc0` and `gpc1` counters:
- `gpc0 = 1` → IP was checked and allowed
- `gpc1 = 1` → IP was checked and blocked

## HTTP Headers

The module sets these headers on each request:

| Header | Description |
|--------|-------------|
| `X-DNSBL-Action` | Result: CACHE-ALLOW, LOOKUP-DENY, etc. |
| `X-DNSBL-Is-Allowed` | 1 if allowed, 0 if blocked |
| `X-DNSBL-Client-IP` | IP address that was checked |
| `X-DNSBL-Query` | DNS query that was made |
| `X-DNSBL-Zone` | Spamhaus zone (if applicable) |
| `X-DNSBL-Description` | Block reason (if applicable) |

## Changelog

### v0.4.0 (Current)

- Added support for `.exitlist.torproject.org` domain
- Added support for Spamhaus domains (sbl, xbl, pbl, zen)
- Added configurable track-sc index (sc0, sc1, sc2)
- Added `X-DNSBL-Zone` and `X-DNSBL-Description` headers
- Added comprehensive documentation and examples

### v0.3.0

- Initial public release
- Support for `.torexit.dan.me.uk` domain

## Known Limitations

- Only A record DNS queries are supported (not AAAA)
- Spamhaus may rate-limit queries from public DNS resolvers

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/dobrevit/haproxy-lua-dnsbl/issues.

## License

MIT License

Copyright (c) 2023 Dobrev IT Ltd., Martin Dobrev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
