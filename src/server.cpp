#include "dns_server.h"
#include "dns_packet.h"
#include <iostream>
#include <string>

int main(int argc, char *argv[]) {
    // 默认参数
    std::string listen_addr = "0.0.0.0";
    int listen_port = 53;
    size_t cache_size = 250;
    int cache_min_ttl = 0;
    int cache_max_ttl = 86400;
    std::string upstream_str; // 上游服务器字符串, 若为空则使用系统 DNS
    std::string proxy_url;

    // 解析参数
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-l" || arg == "--listen") {       // 监听地址
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
    DnsServer server(listen_addr, listen_port, cache_size, cache_min_ttl, cache_max_ttl, upstream, proxy_url);
    server.start();

    return 0;
}
