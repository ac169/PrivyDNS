#include "dns_services.h"
#include "proxy_handler.h"
#include "httplib.h"
#include <iostream>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif

#include <openssl/ssl.h>

DnsResponse query_udp(const std::string &domain, uint16_t qtype, const ServerEndpoint &ep, const std::string &proxy) {
    DnsResponse resp;
    unsigned char packet[512];
    int packet_len = build_dns_packet(domain, qtype, packet, sizeof(packet));
    if (packet_len < 0) return resp;

    std::string p_type, p_host;
    int p_port = 0;
    bool use_proxy = parse_proxy_string(proxy, p_type, p_host, p_port);
    bool route_via_tcp_proxy = (use_proxy && (p_type == "socks5h" || p_type == "socks5"));

    if (route_via_tcp_proxy) {
#ifdef _WIN32
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
        int sock = socket(AF_INET, SOCK_STREAM, 0);
#endif
        if (connect_via_socks5(sock, p_host, p_port, ep.host, ep.port) < 0) {
            std::cerr << "SOCKS5 Proxy negotiation failed for traditional DNS.\n";
#ifdef _WIN32
            closesocket(sock);
#else
            close(sock);
#endif
            return resp;
        }

        std::vector<unsigned char> tcp_send_buf(packet_len + 2);
        tcp_send_buf[0] = (packet_len >> 8) & 0xFF;
        tcp_send_buf[1] = packet_len & 0xFF;
        memcpy(tcp_send_buf.data() + 2, packet, packet_len);

        send(sock, (char *) tcp_send_buf.data(), (int) tcp_send_buf.size(), 0);

        unsigned char len_buf[2];
        recv(sock, (char *) len_buf, 2, 0);
        uint16_t res_len = (len_buf[0] << 8) | len_buf[1];

        std::vector<unsigned char> recv_buf(res_len);
        int bytes_received = 0;
        while (bytes_received < res_len) {
            int r = recv(sock, (char *) recv_buf.data() + bytes_received, res_len - bytes_received, 0);
            if (r <= 0) break;
            bytes_received += r;
        }

        if (bytes_received > 0) {
            parse_dns_response_to_struct(recv_buf.data(), bytes_received, resp);
            resp.server_info = ep.host + "#" + std::to_string(ep.port) + "(" + ep.host + ")";
        }
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    } else {
        struct addrinfo hints, *res = nullptr, *ai;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;      // Allow both IPv4 and IPv6
        hints.ai_socktype = SOCK_DGRAM;

        std::string port_str = std::to_string(ep.port);
        if (getaddrinfo(ep.host.c_str(), port_str.c_str(), &hints, &res) != 0) {
            std::cerr << "Error: Unable to resolve server hostname: " << ep.host << "\n";
            return resp;
        }

        bool success = false;
        for (ai = res; ai != nullptr; ai = ai->ai_next) {
#ifdef _WIN32
            SOCKET sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (sock == INVALID_SOCKET) continue;
#else
            int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (sock < 0) continue;
#endif

            // Set timeout
#ifdef _WIN32
            DWORD timeout = 3000;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(timeout));
#else
            struct timeval tv;
            tv.tv_sec = 3;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

            if (sendto(sock, (char *) packet, packet_len, 0, ai->ai_addr, (int) ai->ai_addrlen) >= 0) {
                unsigned char recv_buf[512];
                int ret = recv(sock, (char *) recv_buf, sizeof(recv_buf), 0);
                if (ret > 0) {
                    parse_dns_response_to_struct(recv_buf, ret, resp);
                    resp.server_info = ep.host + "#" + std::to_string(ep.port) + "(" + ep.host + ")";
                    success = true;
#ifdef _WIN32
                    closesocket(sock);
#else
                    close(sock);
#endif
                    break;
                }
            }
#ifdef _WIN32
            closesocket(sock);
#else
            close(sock);
#endif
        }

        freeaddrinfo(res);
        if (!success) {
            std::cerr << "UDP Direct [" << ep.host << ":" << ep.port << "] Query Failed/Timeout.\n";
        }
    }

    return resp;
}

DnsResponse query_dot(const std::string &domain, uint16_t qtype, const ServerEndpoint &ep, const std::string &proxy) {
    DnsResponse resp;
    unsigned char packet[512];
    int packet_len = build_dns_packet(domain, qtype, packet, sizeof(packet));
    if (packet_len < 0) return resp;

    std::string p_type, p_host;
    int p_port = 0;
    bool use_proxy = parse_proxy_string(proxy, p_type, p_host, p_port);

    // Create a socket placeholder (will be replaced in direct path if needed)
#ifdef _WIN32
    SOCKET sock = INVALID_SOCKET;
#else
    int sock = -1;
#endif

    if (use_proxy) {
        // ===== Proxy path (unchanged; may need enhancement for IPv6 target later) =====
#ifdef _WIN32
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
        sock = socket(AF_INET, SOCK_STREAM, 0);
#endif
        if (p_type == "socks5h" || p_type == "socks5") {
            if (connect_via_socks5(sock, p_host, p_port, ep.host, ep.port) < 0) {
                std::cerr << "SOCKS5 Proxy negotiation failed.\n";
#ifdef _WIN32
                closesocket(sock);
#else
                close(sock);
#endif
                return resp;
            }
        } else if (p_type == "http") {
            if (connect_via_http_proxy(sock, p_host, p_port, ep.host, ep.port) < 0) {
                std::cerr << "HTTP Proxy tunnel negotiation failed.\n";
#ifdef _WIN32
                closesocket(sock);
#else
                close(sock);
#endif
                return resp;
            }
        } else {
            std::cerr << "Unsupported proxy type for DoT raw socket pipeline.\n";
            return resp;
        }
    } else {
        // ===== Direct connection path with IPv6 support =====
        struct addrinfo hints, *res = nullptr, *ai;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;      // Allow both IPv4 and IPv6
        hints.ai_socktype = SOCK_STREAM;

        std::string port_str = std::to_string(ep.port);
        if (getaddrinfo(ep.host.c_str(), port_str.c_str(), &hints, &res) != 0) {
            std::cerr << "Error: Unable to resolve DoT server hostname: " << ep.host << "\n";
            return resp;
        }

        // Try each address until one succeeds
        for (ai = res; ai != nullptr; ai = ai->ai_next) {
#ifdef _WIN32
            SOCKET tmp_sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (tmp_sock == INVALID_SOCKET) continue;
#else
            int tmp_sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (tmp_sock < 0) continue;
#endif

            if (connect(tmp_sock, ai->ai_addr, (int) ai->ai_addrlen) == 0) {
                sock = tmp_sock;   // use this connected socket
                break;
            }
#ifdef _WIN32
            closesocket(tmp_sock);
#else
            close(tmp_sock);
#endif
        }

        freeaddrinfo(res);

        if (sock < 0) {
            std::cerr << "Error: Could not connect to DoT server.\n";
            return resp;
        }
    }

    // ===== TLS handshake and query (unchanged) =====
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int) sock);
    SSL_set_tlsext_host_name(ssl, ep.host.c_str());

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "DoT TLS Handshake failed.\n";
        SSL_free(ssl);
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        SSL_CTX_free(ctx);
        return resp;
    }

    unsigned char dot_buf[514];
    dot_buf[0] = (packet_len >> 8) & 0xFF;
    dot_buf[1] = packet_len & 0xFF;
    memcpy(dot_buf + 2, packet, packet_len);

    SSL_write(ssl, dot_buf, packet_len + 2);

    unsigned char len_buf[2];
    int len_bytes_read = 0;
    while (len_bytes_read < 2) {
        int r = SSL_read(ssl, len_buf + len_bytes_read, 2 - len_bytes_read);
        if (r <= 0) {
            std::cerr << "DoT server terminated connection unexpectedly.\n";
            SSL_free(ssl);
#ifdef _WIN32
            closesocket(sock);
#else
            close(sock);
#endif
            SSL_CTX_free(ctx);
            return resp;
        }
        len_bytes_read += r;
    }

    uint16_t res_len = (len_buf[0] << 8) | len_buf[1];
    std::vector<unsigned char> recv_buf(res_len);
    int body_bytes_read = 0;
    while (body_bytes_read < res_len) {
        int r = SSL_read(ssl, recv_buf.data() + body_bytes_read, res_len - body_bytes_read);
        if (r <= 0) break;
        body_bytes_read += r;
    }

    if (body_bytes_read > 0) {
        parse_dns_response_to_struct(recv_buf.data(), body_bytes_read, resp);
        resp.server_info = ep.host + "#" + std::to_string(ep.port) + "(" + ep.host + ")";
    }

    SSL_free(ssl);
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    SSL_CTX_free(ctx);

    return resp;
}

DnsResponse query_doh(const std::string &domain, uint16_t qtype, const ServerEndpoint &ep, const std::string &proxy) {
    DnsResponse resp;
    unsigned char packet[512];
    int packet_len = build_dns_packet(domain, qtype, packet, sizeof(packet));
    if (packet_len < 0) return resp;

    std::string host_for_url = ep.host;
    if (host_for_url.find(':') != std::string::npos) {
        host_for_url = "[" + host_for_url + "]";
    }
    std::string base_url = "https://" + host_for_url;
    if (ep.port != 443) base_url += ":" + std::to_string(ep.port);

    httplib::Client cli(base_url);
    cli.enable_server_certificate_verification(false);

    std::string p_type, p_host;
    int p_port = 0;
    if (parse_proxy_string(proxy, p_type, p_host, p_port)) {
//        if (p_type == "socks5" || p_type == "socks5h") {
//            cli.set_socks5_proxy(p_host, p_port);
//        } else if (p_type == "http") {
//            cli.set_proxy(p_host, p_port);
//        }
        if (p_type == "http") {
            cli.set_proxy(p_host, p_port);
        } else {
            std::cerr << "Warning: DoH via raw SOCKS5 isn't natively carried by cpp-httplib. Please pass http:// proxy instead for DoH.\n";
        }
    }

    std::string path = ep.path.empty() ? "/dns-query" : ep.path;
    std::string body((char *) packet, packet_len);

    httplib::Headers headers = {
            {"Content-Type", "application/dns-message"},
            {"Accept", "application/dns-message"}
    };

    auto res = cli.Post(path, headers, body, "application/dns-message");

    if (res && res->status == 200) {
//        std::cout << "--- DoH [" << ep.host << path << "] Query Results ---\n";
//        parse_dns_response((unsigned char *) res->body.data(), (int) res->body.length());
        parse_dns_response_to_struct((unsigned char *) res->body.data(), (int) res->body.length(), resp);
        resp.server_info = ep.host + "#" + std::to_string(ep.port) + "(" + ep.host + ")";
    } else {
        std::cerr << "DoH Query failed. HTTP Status or Connection error.\n";
    }

    return resp;
}
