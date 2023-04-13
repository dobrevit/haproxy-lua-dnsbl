# haproxy-lua-dnsbl

DNSBL (DNS blacklisting) module for HAProxy Lua. Dynamically block requests based on the response of the DNS query or use
any of the added extra request headers to make decissions down the line.

# Installation

`haproxy-lua-dnsbl` is depending on [utils](https://github.com/dobrevit/haproxy-lua-utils) and `socket` library. Download
a copy of them in Lua accessible path, for example `/usr/share/lua/5.3/`.

# Usage

Please have a look at the [example](./example/) folder for inspiration how to use this library.

# How it works

The library is using the `socket.dns` class to make DNS queries. The DNSBL domain is configured in the `dnsbl_domain`
variable. The DNSBL domain is expected to return a `NXDOMAIN` response if the IP address is not blacklisted. If the
response is `NXDOMAIN`, the request is allowed to pass through. If there is a response, the request is marked for denying.
Finally, based on the results, the client IP will flip a set of gpc counters that will act as a cache for the next
requests.
You can read more about the design of the library in the [docs](./docs/) section.

# Known limitations

I'm unable to find a reliable way to call `do-resolve` from within Lua, so I decided to fall back to the Lua `socket.dns`
class and use it to make DNS queries. For this reason only A records are supported.
Next to it, although the code is making provisions for configuring the DNSBL domain, only `.torexit.dan.me.uk` is supported.

# TODO

* [X] Add support for `.torexit.dan.me.uk` domain
* [ ] Add support for `.exitlist.torproject.org` domain
* [ ] Add support for `xbl.spamhaus.org` domain
* [ ] Make it possible to configure the cache and ban track-sc index (hard-coded for now)

# Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/dobrevit/haproxy-lua-dnsbl/issues.

# License

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
