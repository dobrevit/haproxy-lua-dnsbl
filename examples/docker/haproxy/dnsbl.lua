-- The MIT License (MIT)
--
-- Copyright (c) 2023 Dobrev IT Ltd., Martin Dobrev
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
--
-- SPDX-License-Identifier: MIT
--
-- Description: DNSBL query and block action
-- Version: 0.4.0
--
-- This is a Haproxy Lua action that prepares a DNSBL query and
-- performs a DNSBL lookup. If the DNSBL lookup returns a positive
-- result, the block action will block the request.
--
-- Supported DNSBL providers:
-- - .torexit.dan.me.uk (Tor exit nodes, response: 127.0.0.100)
-- - .exitlist.torproject.org (Tor exit nodes, response: 127.0.0.2)
-- - *.spamhaus.org (Spamhaus lists, various responses)
--


local _M={}
local utils = require("utils")
local socket = require("socket")
local inspect = require("inspect")

_M.version = "0.4.0"

_M.stktbl_lookup = function(stktbl, key)
    local st_info = stktbl:info()
    if st_info.type == "ipv6" then
        if key:find(".", 1, true) then
            key = '::ffff:' .. key
        end
    elseif st_info.type == "ip" then
        return nil, "stick-table type 'ip' not supported. Use 'type ipv6' instead (supports both IPv4 and IPv6)"
    elseif st_info.type == "string" then
        return nil, "stick-table type 'string' not supported. Use 'type ipv6' instead"
    else
        return nil, "Unsupported stick-table type: " .. tostring(st_info.type) .. ". Use 'type ipv6' instead"
    end

    local entry = stktbl:lookup(key)
    --txn:Debug(string.format("stktbl_lookup result: %s", inspect(entry)))
    if entry then
        return entry
    else
        return nil, "No entry found"
    end
end

_M.spamhaus_response = function(response)
    local spamhaus_response_map = {
        ["127.255.255.252"] = {
            ["zone"] = "Any",
            ["description"] = "Typing error in DNSBL name",
            ["permitted"] = false
        },
        ["127.255.255.254"] = {
            ["zone"] = "Any",
            ["description"] = "Query via public/open resolver",
            ["permitted"] = false
        },
        ["127.255.255.255"] = {
            ["zone"] = "Any",
            ["description"] = "Excessive number of queries",
            ["permitted"] = false
        },
        ["127.0.0.2"] = {
            ["zone"] = "SBL",
            ["description"] = "Spamhaus SBL Data",
            ["permitted"] = false
        },
        ["127.0.0.3"] = {
            ["zone"] = "SBL",
            ["description"] = "Spamhaus SBL CSS Data",
            ["permitted"] = false
        },
        ["127.0.0.4"] = {
            ["zone"] = "XBL",
            ["description"] = "CBL Data",
            ["permitted"] = false
        },
        ["127.0.0.9"] = {
            ["zone"] = "SBL",
            ["description"] = "Spamhaus DROP/EDROP Data (in addition to 127.0.0.2, since 01-Jun-2016)",
            ["permitted"] = false
        },
        ["127.0.0.10"] = {
            ["zone"] = "PBL",
            ["description"] = "ISP Maintained",
            ["permitted"] = false
        },
        ["127.0.0.11"] = {
            ["zone"] = "PBL",
            ["description"] = "Spamhaus Maintained",
            ["permitted"] = false
        }
    }

    if spamhaus_response_map[response] then
        local zone = spamhaus_response_map[response]["zone"]
        local description = spamhaus_response_map[response]["description"]
        local permitted = spamhaus_response_map[response]["permitted"]
        return permitted, zone, description
    else
        return true, nil, nil
    end
end

-- Check if a DNSBL response indicates the IP should be blocked
-- Returns: blocked (boolean), zone (string or nil), description (string or nil)
_M.is_blocked_response = function(response, bl_domain)
    -- Tor exit list from dan.me.uk
    if bl_domain:find("torexit.dan.me.uk", 1, true) then
        if response == "127.0.0.100" then
            return true, "TOR", "Dan.me.uk Tor Exit Node"
        end
        return false, nil, nil
    end

    -- Tor exit list from Tor Project
    if bl_domain:find("exitlist.torproject.org", 1, true) then
        if response == "127.0.0.2" then
            return true, "TOR", "Tor Project Exit Node"
        end
        return false, nil, nil
    end

    -- Spamhaus lists (sbl, xbl, pbl, zen, etc.)
    if bl_domain:find("spamhaus", 1, true) then
        local permitted, zone, description = _M.spamhaus_response(response)
        if not permitted then
            return true, zone, description
        end
        return false, nil, nil
    end

    -- Default: any response in 127.x.x.x range is considered blocked
    if response and response:find("^127%.") then
        return true, "UNKNOWN", "Unknown DNSBL response: " .. response
    end

    return false, nil, nil
end

-- Helper functions for configurable track-sc index
-- These allow using sc0, sc1, or sc2 based on configuration

_M.sc_inc_gpc0 = function(txn, backend, sc_index)
    sc_index = sc_index or 0
    if sc_index == 0 then
        return txn.f:sc0_inc_gpc0(backend)
    elseif sc_index == 1 then
        return txn.f:sc1_inc_gpc0(backend)
    elseif sc_index == 2 then
        return txn.f:sc2_inc_gpc0(backend)
    else
        return txn.f:sc0_inc_gpc0(backend)
    end
end

_M.sc_inc_gpc1 = function(txn, backend, sc_index)
    sc_index = sc_index or 0
    if sc_index == 0 then
        return txn.f:sc0_inc_gpc1(backend)
    elseif sc_index == 1 then
        return txn.f:sc1_inc_gpc1(backend)
    elseif sc_index == 2 then
        return txn.f:sc2_inc_gpc1(backend)
    else
        return txn.f:sc0_inc_gpc1(backend)
    end
end

function dnsbl_query(txn, st_name, bl_domain, src_var, src_header, sc_index)
    -- configuration
    local st_dnsbl_cache = st_name
    local is_new_visitor = false
    local is_allowed = false
    local client_ip = txn:get_var("txn.dnsbl_client_ip")

    -- Parse sc_index (default to 0 if not provided or empty)
    if sc_index == nil or sc_index == "" then
        sc_index = 0
    else
        sc_index = tonumber(sc_index) or 0
    end

    -- get client IP from the source variable (if set)
    if not utils.is_nil(src_var) then
        client_ip = txn:get_var(src_var)
        -- check if src_var exists and is not empty
        if not utils.is_nil(client_ip) then
            --txn:Debug(string.format("DNSBL: client IP: %s\n", client_ip))
            txn:set_var("txn.dnsbl_client_ip", client_ip)
        end
    end

    if utils.is_nil(client_ip) and not utils.is_nil(src_header) then
        client_ip = txn.sf:req_hdr(src_header)
        if not utils.is_nil(client_ip) then
            --txn:Debug(string.format("DNSBL: client IP: %s\n", client_ip))
            txn:set_var("txn.dnsbl_client_ip", client_ip)
        end
    end

    if utils.is_nil(client_ip) then
        client_ip = txn.sf:src()
        --txn:Debug(string.format("DNSBL: client IP: %s\n", client_ip))
        txn:set_var("txn.dnsbl_client_ip", client_ip)
    end
    --txn:Debug(string.format("DNSBL: client IP: %s\n", client_ip))

    local reverse_client_ip, err = utils.reverse_ip(client_ip)

    if not reverse_client_ip then
        txn:Debug(string.format("Error reversing IP: %s\n", err))
        return false
    end

    local query = string.format("%s.%s", reverse_client_ip, bl_domain)

    if core.backends[st_dnsbl_cache] and core.backends[st_dnsbl_cache].stktable then
        local st = core.backends[st_dnsbl_cache].stktable
        local st_lookup, err = _M.stktbl_lookup(st, client_ip)
        if not st_lookup then
            txn:Debug(string.format("stktbl_lookup error: %s. Most likely there isn't track-sc0 set in your HAProxy configuration", err))
            txn.http:req_set_header("X-DNSBL-Action", "DNSBL-ERROR-ALLOW")
            txn.http:req_set_header("X-DNSBL-Error", err)
            is_allowed = true
        else
            --txn:Debug(string.format("st_known_visitors stick-table lookup for %s: %s", client_ip, inspect(st_lookup)))
            if st_lookup.gpc0 == 1 then
                --txn:Debug(string.format("DNSBL: IP %s found in %s cache. ALLOW access", client_ip, bl_domain))
                txn.http:req_set_header("X-DNSBL-Action", "DNSBL-CACHE-ALLOW")
                is_allowed = true
            elseif st_lookup.gpc1 == 1 then
                --txn:Debug(string.format("DNSBL: IP %s found in %s cache. DENY access", client_ip, bl_domain))
                txn.http:req_set_header("X-DNSBL-Action", "DNSBL-CACHE-DENY")
            elseif st_lookup.gpc0 == 0 or st_lookup.gpc1 == 0 then
                --txn:Debug(string.format("DNSBL: IP %s not previously seen in %s cache. LOOKUP required", client_ip, bl_domain))
                is_new_visitor = true
            end
        end
    else
        txn:Debug(string.format("No %s backend with stick-table within", st_dnsbl_cache))
    end

    if is_new_visitor then
        local ip, details = socket.dns.toip(query)
        if not ip then
            if details and details ~= '"host not found"' then
                --txn:Debug(string.format("DNSBL: IP %s not found in %s. Details: %s. ALLOW access", client_ip, bl_domain, inspect(details)))
                txn.http:req_set_header("X-DNSBL-Action", "DNSBL-LOOKUP-ALLOW")
                _M.sc_inc_gpc0(txn, st_dnsbl_cache, sc_index)
                is_allowed = true
            else
                txn:Debug("dnsbl_query: DNS resolution failed: " .. inspect(details))
                return false
            end
        else
            -- Check if this DNSBL response indicates a blocked IP
            local blocked, zone, description = _M.is_blocked_response(ip, bl_domain)
            if blocked then
                --txn:Debug(string.format("DNSBL: IP %s found in %s. DENY access", client_ip, bl_domain))
                txn.http:req_set_header("X-DNSBL-Action", "DNSBL-LOOKUP-DENY")
                _M.sc_inc_gpc1(txn, st_dnsbl_cache, sc_index)
                -- Set additional headers for Spamhaus zone/description
                if zone then
                    txn.http:req_set_header("X-DNSBL-Zone", zone)
                end
                if description then
                    txn.http:req_set_header("X-DNSBL-Description", description)
                end
            else
                --txn:Debug(string.format("DNSBL: Response %s for %s not in block list. ALLOW access", ip, bl_domain))
                txn.http:req_set_header("X-DNSBL-Action", "DNSBL-LOOKUP-ALLOW")
                _M.sc_inc_gpc0(txn, st_dnsbl_cache, sc_index)
                is_allowed = true
            end
        end
    end

    if is_allowed then
        txn.http:req_set_header("X-DNSBL-Is-Allowed", 1)
    else
        txn.http:req_set_header("X-DNSBL-Is-Allowed", 0)
    end

    txn.http:req_set_header("X-DNSBL-Version", _M.version)
    txn.http:req_set_header("X-DNSBL-Client-IP", client_ip)
    txn.http:req_set_header("X-DNSBL-Query", query)

    txn:set_var("txn.dnsbl_is_allowed", is_allowed)
end

function dnsbl_block_banned(txn, st_name)
    local client_ip = txn:get_var("txn.dnsbl_client_ip")
    local is_allowed = txn:get_var("txn.dnsbl_is_allowed")
    local st = core.backends[st_name].stktable
    local st_lookup, err = _M.stktbl_lookup(st, client_ip)

    --txn:Debug(string.format("DNSBL: st_lookup: %s", inspect(st_lookup)))

    if is_allowed == "false" then
        if not st_lookup then
            --txn:Debug(string.format("stktbl_lookup error: %s", err))
            return false
        else
            if st_lookup.gpc0 > 1 then
                --txn:Debug(string.format("DNSBL: IP %s found in %s ban-list. BLOCK request", client_ip, st_name))
                local reply = txn:reply()
                reply:set_status(401, "Unauthorized")
                reply:add_header("Content-Type", "text/html")
                reply:add_header("Server", string.format("DNSBL/%s", _M.version))
                reply:add_header("Denial-Reason", "DNSBL: IP found in hard banlist. BLOCK request")
                txn:done(reply)
            end
        end
    else
        return false
    end
end

core.register_action("dnsbl_query", {"http-req"}, dnsbl_query, 5)
core.register_action("dnsbl_block", {"http-req"}, dnsbl_block_banned, 1)

return _M
