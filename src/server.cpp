#include "dns_server.h"
#include "dns_packet.h"
#include <iostream>
#include <string>

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
    std::cout << "                                  SERVER USAGE\n";
    std::cout << "-------------------------------------------------------------------------------\n";
    std::cout << "  " << prog << " [options]\n\n";
    std::cout << "[OPTIONS]\n";
    std::cout << "  -l, --listen <addr>  Specify local listening interface and port.\n";
    std::cout << "                       Format: IP or IP:PORT (Default: 0.0.0.0:53)\n\n";
    std::cout << "  -s, --upstream <url> Specify remote upstream DNS backend endpoint.\n";
    std::cout << "                       - UDP: 223.5.5.5 or 8.8.8.8:53\n";
    std::cout << "                       - DoH: https://your-domain.com\n";
    std::cout << "                       - DoT: tls://dns.google\n\n";
    std::cout << "  -x, --proxy <url>    Upstream proxy tunnel redirection routing.\n";
    std::cout << "                       Supports: http://127.0.0.1:1081 or socks5h://127.0.0.1:1080\n\n";
    std::cout << "  -m, --mgmt <port>    Specify local TCP management console port.\n";
    std::cout << "                       Accepts commands like 'quit' (Default: 953)\n\n";
    std::cout << "  -e, --ecs <subnet>   Enforce a global public fallback subnet for local private queries.\n";
    std::cout << "                       Supports IPv4 or IPv6 with masks, e.g.,\n";
    std::cout << "                       -v4: 116.228.0.0/24, 114.114.114.114/32\n";
    std::cout << "                       -v6: 240e:c2:2000::/48\n\n";
    std::cout << "  --cache-size <num>   Configure maximum records inside the internal cache (Default: 250)\n";
    std::cout << "  --cache-min-ttl <s>  Force override the lower boundary of record storage lifetime in seconds\n";
    std::cout << "  --cache-max-ttl <s>  Force override the upper boundary of record storage lifetime in seconds\n\n";
    std::cout << "  -h, --help           Show this help message and exit.\n\n";
    std::cout << "-------------------------------------------------------------------------------\n";
    std::cout << "                         CRITICAL ARCHITECTURE MATRIX:\n";
    std::cout << "-------------------------------------------------------------------------------\n\n";
    std::cout << "1. Multi-Threaded Dual Binding:\n";
    std::cout << "   - The service concurrently binds UDP and TCP listeners to the identical local port.\n";
    std::cout << "   - Standard computer endpoints default to raw UDP traffic for maximum transmission.\n\n";
    // Avoid Chinese punctuation inside descriptions below
    std::cout << "2. Tiered EDNS Cascade Priority:\n";
    std::cout << "   - Priority 1: Retain raw subnet definitions if explicit client EDNS is present\n";
    std::cout << "   - Priority 2: Inject global override subnet provided via the explicit '-e' argument\n";
    std::cout << "   - Priority 3: Fallback natively to public IP strings for direct external queries\n\n";
    std::cout << "3. Management Safe Teardown:\n";
    std::cout << "   - Echo 'quit' toward localhost to terminate all tracking daemon runtime state machines safely\n";
}

int main(int argc, char *argv[]) {
    // 默认参数
    std::string listen_addr = "0.0.0.0";
    int listen_port = 53;
    size_t cache_size = 250;
    int cache_min_ttl = 0;
    int cache_max_ttl = 86400;
    std::string upstream_str; // 上游服务器字符串, 若为空则使用系统 DNS
    std::string proxy_url;
    int mgmt_port = 953;
    std::string ecs_ip = "";
    uint8_t ecs_mask = 0;

    // 解析参数
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (arg == "-l" || arg == "--listen") {
            if (i + 1 < argc) {
                std::string addr = argv[++i];
                size_t colon = addr.find(':');
                if (colon != std::string::npos) {
                    listen_addr = addr.substr(0, colon);
                    listen_port = std::stoi(addr.substr(colon + 1));
                } else {
                    listen_addr = addr;
                }
            }
        } else if (arg == "--cache-size") {
            if (i + 1 < argc) cache_size = std::stoul(argv[++i]);
        } else if (arg == "--cache-min-ttl") {
            if (i + 1 < argc) cache_min_ttl = std::stoi(argv[++i]);
        } else if (arg == "--cache-max-ttl") {
            if (i + 1 < argc) cache_max_ttl = std::stoi(argv[++i]);
        } else if (arg == "-s" || arg == "--upstream") {
            if (i + 1 < argc) upstream_str = argv[++i];
        } else if (arg == "-x" || arg == "--proxy") {
            if (i + 1 < argc) proxy_url = argv[++i];
        } else if (arg == "-m" || arg == "--mgmt") {
            if (i + 1 < argc) mgmt_port = std::stoi(argv[++i]);
        } else if (arg == "-e" || arg == "--ecs") {
            if (i + 1 < argc) {
                std::string ecs_arg = argv[++i];
                size_t slash_pos = ecs_arg.find('/');
                if (slash_pos != std::string::npos) {
                    ecs_ip = ecs_arg.substr(0, slash_pos);
                    ecs_mask = (uint8_t) std::stoi(ecs_arg.substr(slash_pos + 1));
                } else {
                    ecs_ip = ecs_arg;
                    /* Check colon for ipv6 features */
                    ecs_mask = (ecs_ip.find(':') != std::string::npos) ? 64 : 24;
                }
            }
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return 1;
        }
    }

    // 确定上游服务器
    ServerEndpoint upstream;
    if (upstream_str.empty()) {
        upstream = parse_server_string(""); // 使用系统 DNS
    } else {
        upstream = parse_server_string(upstream_str);
    }

    // 启动服务器
    DnsServer server(listen_addr, listen_port, cache_size, cache_min_ttl, cache_max_ttl, upstream, proxy_url, mgmt_port, ecs_ip, ecs_mask);
    server.start();

    return 0;
}
