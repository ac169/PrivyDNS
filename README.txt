===============================================================================
                       Multi-Protocol DNS Lookup Tool
===============================================================================

[BASIC USAGE]
  dns_query.exe [options] <domain>

[OPTIONS]
  -s, --server <url>   Specify remote DNS server endpoint.
                       - UDP: 223.5.5.5 or 8.8.8.8:53 (Default if omitted)
                       - DoH: https://alidns.com
                       - DoT: tls://dns.quad9.net
                       - DNSCrypt: sdns://AQIAAAAAAAAA...

  -t, --type <type>    Query record type: A, AAAA, CNAME, TXT, MX.
                       (If omitted, automatically executes dual-stack A + AAAA)

  -x, --proxy <url>    Upstream proxy tunnel redirection routing.
                       Supports: http://127.0.0.1:1081 or socks5h://127.0.0.1:1080

-------------------------------------------------------------------------------
⚠️ [CRITICAL PROXY SURVIVAL NOTES / 代理使用核心注意事项]
-------------------------------------------------------------------------------

1. DoH (DNS over HTTPS) Protocol Constraints:
   - DoH in this program relies heavily on the 'cpp-httplib' standalone framework.
   - cpp-httplib does NOT support raw SOCKS5 proxies natively due to explicit HTTP
     layer mapping constraints.
   - FIX / WORKAROUND: If you pass a SOCKS5 proxy to a DoH server, the request
     will drop or fail to build headers. You MUST supply an HTTP proxy instead,
     e.g., -x http://127.0.0.1:1081 (Clash/v2ray usually opens an HTTP port
     alongside SOCKS5).

2. DoT (DNS over TLS) & Traditional UDP Protocols:
   - These pathways bypass the HTTP layers entirely and operate over our
     handwritten pure C++ socket state machines.
   - SOCKS5h RECOMMENDATION: It is highly encouraged to pass '-x socks5h://...'
     rather than plain 'socks5://'. The trailing 'h' forces the proxy node to
     resolve the DNS server hostname (like dns.quad9.net) REMOTELY, completely
     bypassing and shielding your local host from local DNS hijacking.

3. Port Alignment Matrix:
   - If no explicit port delimiter ':' is supplied in the URL, the program
     automatically pins the official global secure port matrix defaults:
     * udp://  ➔ Port 53
     * tls://  ➔ Port 853
     * https://➔ Port 443
===============================================================================
