#include "proxy_handler.h"
#include <vector>
#include <cstring>
#include <iostream>

#ifndef _WIN32
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#ifdef _WIN32

int connect_via_socks5(SOCKET sock, const std::string &p_host, int p_port, const std::string &t_host, int t_port) {
#else
    int connect_via_socks5(int sock, const std::string& p_host, int p_port, const std::string& t_host, int t_port) {
#endif
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(p_port);
    proxy_addr.sin_addr.s_addr = inet_addr(p_host.c_str());

    if (connect(sock, (struct sockaddr *) &proxy_addr, sizeof(proxy_addr)) < 0) return -1;

    /* 1. SOCKS5 Greeting Method Selection */
    unsigned char greeting[] = {0x05, 0x01, 0x00};
    send(sock, (char *) greeting, 3, 0);

    unsigned char response[2];
    recv(sock, (char *) response, 2, 0);
    if (response[0] != 0x05 || response[1] != 0x00) return -1;

    /* 2. SOCKS5 Request Header */
    std::vector<unsigned char> req = {0x05, 0x01, 0x00}; // VER, CMD(CONNECT), RSV

    /* True socks5h remote resolution implementation. */
    /* Check if target host is a valid pure IPv4 address. If not, treat as domain name */
    uint32_t target_ip = inet_addr(t_host.c_str());
    if (target_ip != INADDR_NONE) {
        /* If it's a numeric IP, use ATYP = 0x01 (IPv4) */
        req.push_back(0x01); // ATYP: IPv4
        req.insert(req.end(), (unsigned char *) &target_ip, (unsigned char *) &target_ip + 4);
    } else {
        /* If it's a domain name (://alidns.com), use ATYP = 0x03 (Domain Name) */
        req.push_back(0x03); // ATYP: Domain Name

        /* Insert 1-byte Domain Length descriptor followed by the hostname string bytes */
        unsigned char host_len = (unsigned char) t_host.length();
        req.push_back(host_len);
        req.insert(req.end(), t_host.begin(), t_host.end());
    }

    /* Target Port (2 bytes, Network Byte Order) */
    uint16_t target_port = htons(t_port);
    req.insert(req.end(), (unsigned char *) &target_port, (unsigned char *) &target_port + 2);

    /* Send the fully compliant remote routing packet */
    send(sock, (char *) req.data(), (int) req.size(), 0);

    unsigned char conn_res[10];
    recv(sock, (char *) conn_res, 10, 0);

    return (conn_res[1] == 0x00) ? 0 : -1; // conn_res[1] is the REP status field
}

#ifdef _WIN32
int connect_via_http_proxy(SOCKET sock, const std::string &p_host, int p_port, const std::string &t_host, int t_port) {
#else
    int connect_via_http_proxy(int sock, const std::string& p_host, int p_port, const std::string& t_host, int t_port) {
#endif
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(p_port);
    proxy_addr.sin_addr.s_addr = inet_addr(p_host.c_str());

    if (connect(sock, (struct sockaddr *) &proxy_addr, sizeof(proxy_addr)) < 0) return -1;

    /* Construct the standard HTTP CONNECT header */
    char req_buf[512];
    int req_len = snprintf(req_buf, sizeof(req_buf), "CONNECT %s:%d HTTP/1.1\r\n"
                                                     "Host: %s:%d\r\n"
                                                     "User-Agent: mydig/1.0\r\n"
                                                     "\r\n", t_host.c_str(), t_port, t_host.c_str(), t_port);

    if (send(sock, req_buf, req_len, 0) < 0) return -1;

    /* Read the response line by line or look for HTTP/1.1 200 */
    char res_buf[1024];
    memset(res_buf, 0, sizeof(res_buf));

    /* Read enough bytes to verify the status line */
    int bytes_received = recv(sock, res_buf, sizeof(res_buf) - 1, 0);
    if (bytes_received <= 0) return -1;

    /* Check if the proxy successfully established the tunnel */
    if (strstr(res_buf, "HTTP/1.1 200") != NULL || strstr(res_buf, "HTTP/1.0 200") != NULL) {
        return 0; /* Tunnel success */
    }

    return -1;
}
