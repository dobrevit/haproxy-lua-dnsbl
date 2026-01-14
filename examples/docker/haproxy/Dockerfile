# HAProxy with Lua DNSBL Module
FROM haproxy:2.8-alpine

# Install Lua and socket library
RUN apk add --no-cache \
    lua5.3 \
    lua5.3-socket \
    curl \
    socat

# Create Lua modules directory
RUN mkdir -p /usr/share/lua/5.3

# Download dependencies
WORKDIR /usr/share/lua/5.3

# Download utils.lua (haproxy-lua-utils)
RUN curl -sL -o utils.lua \
    https://raw.githubusercontent.com/dobrevit/haproxy-lua-utils/main/src/utils.lua

# Download inspect.lua (for debugging)
RUN curl -sL -o inspect.lua \
    https://raw.githubusercontent.com/kikito/inspect.lua/master/inspect.lua

# Copy DNSBL module (from parent directory in build context)
COPY dnsbl.lua /usr/share/lua/5.3/dnsbl.lua

# Copy HAProxy configuration
COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg

# Create socket directory for stats
RUN mkdir -p /var/run/haproxy

# Verify configuration
RUN haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg

# Default command
CMD ["haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]
