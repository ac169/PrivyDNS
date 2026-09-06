#include "dns_server.h"
#include "dns_services.h"
#include <iostream>
#include <cstring>
#include <thread>
#include <ctime>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include <openssl/ssl.h>

#ifdef _WIN32
#define CLOSE_SOCKET(s) closesocket(s)
typedef SOCKET socket_t;
#else
#define CLOSE_SOCKET(s) close(s)
typedef int socket_t;
#endif

DnsServer::DnsServer(const std::string &listen_addr, int port, size_t cache_size, int min_ttl, int max_ttl, const ServerEndpoint &upstream, const std::string &proxy, int mgmt_port) : listen_addr_(listen_addr),
                                                                                                                                                                        port_(port), cache_(cache_size, min_ttl, max_ttl),
                                                                                                                                                                        upstream_(upstream),
                                                                                                                                                                        proxy_(proxy), mgmt_port_(mgmt_port) {}

void DnsServer::start() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    // Create UDP socket
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        std::cerr << "Error creating UDP socket.\n";
        return;
    }
    // Create TCP listening socket
    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) {
        std::cerr << "Error creating TCP socket.\n";
        CLOSE_SOCKET(udp_sock);
        return;
    }

    // Bind UDP
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (listen_addr_ == "0.0.0.0" || listen_addr_.empty()) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, listen_addr_.c_str(), &addr.sin_addr);
    }
    if (bind(udp_sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        std::cerr << "Error binding UDP socket to port " << port_ << "\n";
        CLOSE_SOCKET(udp_sock);
        CLOSE_SOCKET(tcp_sock);
        return;
    }

    // Bind TCP
    if (bind(tcp_sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        std::cerr << "Error binding TCP socket to port " << port_ << "\n";
        CLOSE_SOCKET(udp_sock);
        CLOSE_SOCKET(tcp_sock);
        return;
    }
    if (listen(tcp_sock, 10) < 0) {
        std::cerr << "Error listening on TCP socket.\n";
        CLOSE_SOCKET(udp_sock);
        CLOSE_SOCKET(tcp_sock);
        return;
    }

    // Create management socket (local only)
    int mgmt_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (mgmt_sock >= 0) {
        int opt = 1;
        setsockopt(mgmt_sock, SOL_SOCKET, SO_REUSEADDR, (const char *) &opt, sizeof(opt));
        struct sockaddr_in mgmt_addr;
        memset(&mgmt_addr, 0, sizeof(mgmt_addr));
        mgmt_addr.sin_family = AF_INET;
        mgmt_addr.sin_port = htons(mgmt_port_);
        inet_pton(AF_INET, "127.0.0.1", &mgmt_addr.sin_addr);
        if (bind(mgmt_sock, (struct sockaddr *) &mgmt_addr, sizeof(mgmt_addr)) < 0 || listen(mgmt_sock, 5) < 0) {
            std::cerr << "Warning: Failed to bind management port " << mgmt_port_ << "\n";
            CLOSE_SOCKET(mgmt_sock);
            mgmt_sock = -1;
        }
    }

    std::cout << "DNS server started on " << listen_addr_ << ":" << port_ << "\n";
    std::cout << "Cache size: " << cache_.size() << " (max configured)\n";
    std::cout << "Upstream: " << upstream_.protocol << "://" << upstream_.host << ":" << upstream_.port << upstream_.path << "\n";

    if (mgmt_sock >= 0) {
        std::cout << "Management port: " << mgmt_port_ << "\n" << std::endl;
    }

    // Shared running flag (so management can quit later)
    std::atomic<bool> running{true};

    // Start UDP and TCP threads
    std::thread udp_thread([&]() {
        handle_udp(udp_sock);
    });
    std::thread tcp_thread([&]() {
        handle_tcp(tcp_sock);
    });

    // Start management thread if socket available
    std::thread mgmt_thread;
    if (mgmt_sock >= 0) {
        mgmt_thread = std::thread([&]() {
            handle_management(mgmt_sock, running);   // pass running to allow quit
        });
    }

    // Main thread waits until quit command is received
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Cleanup
    running = false;
    CLOSE_SOCKET(udp_sock);
    CLOSE_SOCKET(tcp_sock);
    if (mgmt_sock >= 0) {
        CLOSE_SOCKET(mgmt_sock);
    }

    udp_thread.join();
    tcp_thread.join();
    if (mgmt_thread.joinable()) {
        mgmt_thread.join();
    }
}

void DnsServer::handle_udp(int udp_sock) {
    unsigned char buffer[512];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while (true) {
        int n = recvfrom(udp_sock, (char *) buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, &client_len);
        if (n < 0) continue;
        unsigned char response[512];
        int response_len = 0;

        char client_ip[INET6_ADDRSTRLEN] = {0};
        if (client_addr.sin_family == AF_INET) {
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        } else if (client_addr.sin_family == AF_INET6) {
            struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&client_addr;
            inet_ntop(AF_INET6, &addr6->sin6_addr, client_ip, sizeof(client_ip));
        }
        process_query(buffer, n, response, &response_len, std::string(client_ip));

        if (response_len > 0) {
            sendto(udp_sock, (char *) response, response_len, 0, (struct sockaddr *) &client_addr, client_len);
        }
    }
}

void DnsServer::handle_tcp(int tcp_sock) {
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(tcp_sock, (struct sockaddr *) &client_addr, &client_len);
        if (client_fd < 0) continue;

        // Read length prefix (2 bytes)
        unsigned char len_buf[2];
        int len_read = recv(client_fd, (char *) len_buf, 2, 0);
        if (len_read != 2) {
            CLOSE_SOCKET(client_fd);
            continue;
        }
        uint16_t query_len = (len_buf[0] << 8) | len_buf[1];
        if (query_len == 0 || query_len > 512) {
            CLOSE_SOCKET(client_fd);
            continue;
        }
        unsigned char query[512];
        int total = 0;
        while (total < query_len) {
            int r = recv(client_fd, (char *) query + total, query_len - total, 0);
            if (r <= 0) break;
            total += r;
        }
        if (total == query_len) {
            unsigned char response[512];
            int response_len = 0;

            char client_ip[INET6_ADDRSTRLEN] = {0};
            if (client_addr.sin_family == AF_INET) {
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
            } else if (client_addr.sin_family == AF_INET6) {
                struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&client_addr;
                inet_ntop(AF_INET6, &addr6->sin6_addr, client_ip, sizeof(client_ip));
            }
            process_query(query, query_len, response, &response_len, std::string(client_ip));

            if (response_len > 0) {
                unsigned char resp_len_buf[2];
                resp_len_buf[0] = (response_len >> 8) & 0xFF;
                resp_len_buf[1] = response_len & 0xFF;
                send(client_fd, (char *) resp_len_buf, 2, 0);
                send(client_fd, (char *) response, response_len, 0);
            }
        }
        CLOSE_SOCKET(client_fd);
    }
}

void DnsServer::handle_management(int mgmt_sock, std::atomic<bool> &running) {
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(mgmt_sock, (struct sockaddr *) &client_addr, &client_len);
        if (client_fd < 0) {
            if (!running) break;
            continue;
        }

        // 可选：限制仅本地连接
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        if (std::string(client_ip) != "127.0.0.1" && std::string(client_ip) != "::1") {
            CLOSE_SOCKET(client_fd);
            continue;
        }

        // 读取一行命令
        std::string cmd;
        char buf[1024];
        int n = recv(client_fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            cmd = buf;
            while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r')) cmd.pop_back();

            // 处理 quit 命令直接设置 running = false
            if (cmd == "quit") {
                running = false;
                std::string response = "OK: server shutting down\n";
                send(client_fd, response.c_str(), response.length(), 0);
                CLOSE_SOCKET(client_fd);
                break;
            }

            std::string response = process_management_command(cmd);
            send(client_fd, response.c_str(), response.length(), 0);
        }
        CLOSE_SOCKET(client_fd);
    }
}

void DnsServer::process_query(const unsigned char *query, int query_len, unsigned char *response, int *response_len, const std::string &client_ip) {
    std::string domain;
    uint16_t qtype;
    if (parse_dns_query(query, query_len, domain, qtype) != 0) {
        *response_len = 0;
        return;
    }

    DnsResponse resp;

    // 1. 先检查缓存
    DnsResponse cached;
    if (cache_.get(domain, qtype, cached)) {
        resp = cached;
        // 保持原始查询 ID
        resp.header.id = (query[0] << 8) | query[1];
    } else {
        // 2. 缓存未命中, 向上游查询
        resp = resolve_upstream(domain, qtype);
        if (resp.valid) {
            // 缓存结果 (保留原始 ID, 但缓存时 ID 不重要, 后续会覆盖)
            cache_.put(domain, qtype, resp);
        } else {
            // 3. 上游失败, 构造 SERVFAIL 响应
            resp = DnsResponse();
            resp.valid = true;
            resp.header.id = (query[0] << 8) | query[1];
            resp.header.flags = 0x8182;   // QR=1, RD=1, RCODE=2
            resp.header.qdcount = 1;
            resp.header.ancount = 0;
            resp.header.nscount = 0;
            resp.header.arcount = 0;
            resp.header.qr = true;
            resp.header.opcode = 0;
            resp.header.aa = false;
            resp.header.tc = false;
            resp.header.rd = true;
            resp.header.ra = false;
            resp.header.rcode = 2;
            DnsQuestion q;
            q.name = domain;
            q.qtype = qtype;
            q.qclass = 1;
            resp.questions.push_back(q);
        }
        // 确保响应 ID 与查询一致(缓存或上游返回时可能已经设置, 但再次确保)
        resp.header.id = (query[0] << 8) | query[1];
    }

    // 序列化响应到输出缓冲区
    int len = build_dns_response(resp, response, 512);
    if (len > 0) {
        *response_len = len;
    } else {
        // 序列化失败(例如不支持的记录类型), 构造最小 SERVFAIL 响应
        DnsResponse fail_resp;
        fail_resp.valid = true;
        fail_resp.header.id = (query[0] << 8) | query[1];
        fail_resp.header.flags = 0x8182;
        fail_resp.header.qdcount = 1;
        fail_resp.header.ancount = 0;
        fail_resp.header.nscount = 0;
        fail_resp.header.arcount = 0;
        fail_resp.header.qr = true;
        fail_resp.header.opcode = 0;
        fail_resp.header.aa = false;
        fail_resp.header.tc = false;
        fail_resp.header.rd = true;
        fail_resp.header.ra = false;
        fail_resp.header.rcode = 2;
        DnsQuestion q;
        q.name = domain;
        q.qtype = qtype;
        q.qclass = 1;
        fail_resp.questions.push_back(q);
        len = build_dns_response(fail_resp, response, 512);
        *response_len = (len > 0) ? len : 0;
        resp = fail_resp;
    }

    // 输出查询日志
    std::string rcode_str;
    switch (resp.header.rcode) {
        case 0:
            rcode_str = "NOERROR";
            break;
        case 1:
            rcode_str = "FORMERR";
            break;
        case 2:
            rcode_str = "SERVFAIL";
            break;
        case 3:
            rcode_str = "NXDOMAIN";
            break;
        case 4:
            rcode_str = "NOTIMP";
            break;
        case 5:
            rcode_str = "REFUSED";
            break;
        default:
            rcode_str = "UNKNOWN";
    }
    std::string answers_str;
    if (qtype == 0x0001 || qtype == 0x001C) { // A or AAAA query
        // Only include A/AAAA records (skip CNAME etc.)
        for (const auto &rec : resp.answers) {
            if (rec.type == 0x0001 || rec.type == 0x001C) {
                if (!answers_str.empty()) answers_str += ", ";
                answers_str += rec.rdata_str;
            }
        }
    } else {
        // For other query types, include all answer records
        for (const auto &rec : resp.answers) {
            if (!answers_str.empty()) answers_str += ", ";
            answers_str += rec.rdata_str;
        }
    }
    if (answers_str.empty()) answers_str = "-";

    // 获取当前时间(本地时间字符串)
    std::time_t now = std::time(nullptr);
    std::tm tm_now{};
#ifdef _WIN32
    localtime_s(&tm_now, &now);
#else
    localtime_r(&now, &tm_now);
#endif
    std::string time_str = current_time_str();

    std::cout << "[" << time_str << "] client=" << client_ip << " query=" << domain << " type=" << qtype_to_str(qtype) << " rcode=" << rcode_str << " answers=" << answers_str << std::endl;
}

DnsResponse DnsServer::resolve_upstream(const std::string &domain, uint16_t qtype) {
//    std::cerr << "[DEBUG] Resolving upstream: " << domain << " type=" << qtype << " via " << upstream_.protocol << " host=" << upstream_.host << " port=" << upstream_.port << " path="
//              << upstream_.path << "\n";
    DnsResponse resp;
    if (upstream_.protocol == "tls") {
        resp = query_dot(domain, qtype, upstream_, proxy_);
    } else if (upstream_.protocol == "https") {
        resp = query_doh(domain, qtype, upstream_, proxy_);
    } else {
        resp = query_udp(domain, qtype, upstream_, proxy_);
    }
//    std::cerr << "[DEBUG] Upstream valid=" << resp.valid << ", answers=" << resp.answers.size() << "\n";
    return resp;
}

//void DnsServer::cache_management_loop(std::atomic<bool> &running) {
//    std::string line;
//    while (running && std::getline(std::cin, line)) {
//        if (line == "list") {
//            auto entries = cache_.list();
//            if (entries.empty()) {
//                std::cout << "Cache is empty.\n";
//            } else {
//                for (const auto &e: entries) std::cout << e << "\n";
//            }
//        } else if (line == "clear") {
//            cache_.clear();
//            std::cout << "Cache cleared.\n";
//        } else if (line == "quit") {
//            running = false;
//        } else if (line.rfind("del ", 0) == 0) {
//            // format: del domain [type]
//            std::istringstream iss(line.substr(4));
//            std::string domain, type_str;
//            iss >> domain;
//            uint16_t qtype = 0x0001; // default A
//            if (iss >> type_str) {
//                qtype = str_to_qtype(type_str);
//            }
//            if (cache_.remove(domain, qtype)) {
//                std::cout << "Removed cache entry for " << domain << " " << qtype_to_str(qtype) << "\n";
//            } else {
//                std::cout << "Entry not found.\n";
//            }
//        } else {
//            std::cout << "Unknown command.\n";
//        }
//    }
//}

std::string DnsServer::current_time_str() const {
    std::time_t now = std::time(nullptr);
    std::tm tm_now{};
#ifdef _WIN32
    localtime_s(&tm_now, &now);
#else
    localtime_r(&now, &tm_now);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_now);
    return std::string(buf);
}

std::string DnsServer::process_management_command(const std::string &cmd) {
    std::istringstream iss(cmd);
    std::string action;
    iss >> action;

    if (action == "list") {
        auto entries = cache_.list();
        if (entries.empty()) return "Cache is empty.\n";
        std::string result;
        for (const auto &e: entries) {
            result += e + "\n";
        }
        return result;
    } else if (action == "clear") {
        cache_.clear();
        return "OK: cache cleared\n";
    } else if (action == "del") {
        std::string domain;
        std::string type_str;
        iss >> domain;
        uint16_t qtype = 0x0001;
        if (iss >> type_str) {
            qtype = str_to_qtype(type_str);
        }
        if (cache_.remove(domain, qtype)) {
            return "OK: removed " + domain + " " + qtype_to_str(qtype) + "\n";
        } else {
            return "Not found\n";
        }
    } else if (action == "status") {
        return "Cache size: " + std::to_string(cache_.size()) + "\n";
    } else {
        return "Unknown command. Available: list, del <domain> [type], clear, status\n";
    }
}
