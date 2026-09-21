#include <iostream>
#include <string>
#include <cstring>
#include "dns_packet.h"
#include "dns_services.h"

#ifdef _WIN32
#include <winsock2.h>
#endif

#include <openssl/ssl.h>


std::string get_base_name(const char *path) {
    std::string p = path;
    size_t pos = p.find_last_of("/\\");
    if (pos != std::string::npos) {
        return p.substr(pos + 1);
    }
    return p;
}

void print_help(const char *program_path) {
    std::string prog = get_base_name(program_path);

    std::cout << "\n-------------------------------------------------------------------------------\n";
    std::cout << "                                  BASIC USAGE\n";
    std::cout << "-------------------------------------------------------------------------------\n";
    std::cout << "  " << prog << " [options] <domain>\n\n";
    std::cout << "[OPTIONS]\n";
    std::cout << "  -s, --server <url>   Specify remote DNS server endpoint.\n";
    std::cout << "                       - UDP: 223.5.5.5 or 8.8.8.8:53 (Default if omitted)\n";
    std::cout << "                       - DoH: https://alidns.com\n";
    std::cout << "                       - DoT: tls://dns.quad9.net\n";
    std::cout << "                       - DNSCrypt: sdns://AQIAAAAAAAAA...\n\n";
    std::cout << "  -t, --type <type>    Query record type: A, AAAA, CNAME, TXT, MX.\n";
    std::cout << "                       (If omitted, automatically executes dual-stack A + AAAA)\n\n";
    std::cout << "  -x, --proxy <url>    Upstream proxy tunnel redirection routing.\n";
    std::cout << "                       Supports: http://127.0.0.1:1081 or socks5h://127.0.0.1:1080\n\n";
    std::cout << "  -e, --ecs <subnet>   Attach EDNS Client Subnet to bypass geo-blocking/CDN slowdown.\n";
    std::cout << "                       Supports IPv4 or IPv6 with masks, e.g.,\n";
    std::cout << "                       -v4: 223.5.5.0/24, 114.114.114.114/32\n";
    std::cout << "                       -v6: 240e:c2:2000::/48\n\n";
    std::cout << "  -h, --help           Show this help message and exit.\n\n";
    std::cout << "-------------------------------------------------------------------------------\n";
    std::cout << "                         CRITICAL PROXY SURVIVAL NOTES:\n";
    std::cout << "-------------------------------------------------------------------------------\n\n";
    std::cout << "1. DoH (DNS over HTTPS) Protocol Constraints:\n";
    std::cout << "   - DoH relies heavily on the 'cpp-httplib' standalone framework.\n";
    std::cout << "   - cpp-httplib does NOT support raw SOCKS5 proxies natively.\n";
    std::cout << "   - You MUST supply an HTTP proxy instead, e.g., -x http://127.0.0.1:1081\n\n";
    std::cout << "2. DoT (DNS over TLS) & Traditional UDP Protocols:\n";
    std::cout << "   - These pathways operate over handwritten pure C++ socket state machines.\n";
    std::cout << "   - SOCKS5h RECOMMENDATION: Pass '-x socks5h://...' to force remote resolution.\n\n";
    std::cout << "3. Port Alignment Matrix:\n";
    std::cout << "   - udp://   -> Port 53\n";
    std::cout << "   - tls://   -> Port 853\n";
    std::cout << "   - https:// -> Port 443\n";
}

int main(int argc, char *argv[]) {
    std::string domain = "";
    std::string server_arg = "";
    std::string proxy_url = "";
    std::string type_arg = "";

    std::string ecs_ip = "";
    uint8_t ecs_mask = 0;

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    SSL_library_init();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
#ifdef _WIN32
            WSACleanup();
#endif
            return 0;
        } else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--server") == 0) && i + 1 < argc) {
            server_arg = argv[++i];
        } else if ((strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "--proxy") == 0) && i + 1 < argc) {
            proxy_url = argv[++i];
        } else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--type") == 0) && i + 1 < argc) {
            type_arg = argv[++i];
        } else if ((strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--ecs") == 0) && i + 1 < argc) {
            std::string ecs_arg = argv[++i];
            size_t slash_pos = ecs_arg.find('/');
            if (slash_pos != std::string::npos) {
                // 如果带有斜杠 (如 223.5.5.0/24) 分别截取 IP 与 掩码
                ecs_ip = ecs_arg.substr(0, slash_pos);
                ecs_mask = (uint8_t) std::stoi(ecs_arg.substr(slash_pos + 1));
            } else {
                // 如果只传了 IP 没有斜杠, 自动根据是 v4 还是 v6 给定默认掩码
                ecs_ip = ecs_arg;
                ecs_mask = (ecs_ip.find(':') != std::string::npos) ? 64 : 24;
            }
        } else if (argv[i][0] != '-') {
            domain = argv[i];
        }
    }

    if (domain.empty()) {
        std::cout << "Error: Target domain required.\nUsage: " << argv[0] << " [options] <domain>\n";
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    size_t clean_pos = domain.find("://");
    if (clean_pos != std::string::npos) domain = domain.substr(clean_pos + 3);


    ServerEndpoint ep = parse_server_string(server_arg);

    if (ep.protocol == "tls") {
        if (!type_arg.empty()) {
            DnsResponse resp = query_dot(domain, str_to_qtype(type_arg), ep, proxy_url, ecs_ip, ecs_mask);
            print_dns_response(resp);
        } else {
            DnsResponse resp_a = query_dot(domain, 0x0001, ep, proxy_url, ecs_ip, ecs_mask);
            DnsResponse resp_aaaa = query_dot(domain, 0x001C, ep, proxy_url, ecs_ip, ecs_mask);
            print_dns_responses({resp_a, resp_aaaa});
        }
    } else if (ep.protocol == "https") {
        if (!type_arg.empty()) {
            DnsResponse resp = query_doh(domain, str_to_qtype(type_arg), ep, proxy_url, ecs_ip, ecs_mask);
            print_dns_response(resp);
        } else {
            DnsResponse resp_a = query_doh(domain, 0x0001, ep, proxy_url, ecs_ip, ecs_mask);
            DnsResponse resp_aaaa = query_doh(domain, 0x001C, ep, proxy_url, ecs_ip, ecs_mask);
            print_dns_responses({resp_a, resp_aaaa});
        }
    } else {
        if (!type_arg.empty()) {
            DnsResponse resp = query_udp(domain, str_to_qtype(type_arg), ep, proxy_url, ecs_ip, ecs_mask);
            print_dns_response(resp);
        } else {
            DnsResponse resp_a = query_udp(domain, 0x0001, ep, proxy_url, ecs_ip, ecs_mask);
            DnsResponse resp_aaaa = query_udp(domain, 0x001C, ep, proxy_url, ecs_ip, ecs_mask);
            print_dns_responses({resp_a, resp_aaaa});
        }
    }


#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
