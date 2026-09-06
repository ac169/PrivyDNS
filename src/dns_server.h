#ifndef DNS_QUERY_DNS_SERVER_H
#define DNS_QUERY_DNS_SERVER_H

#include <string>
#include <atomic>
#include "dns_cache.h"
#include "dns_packet.h"

class DnsServer {
public:
    DnsServer(const std::string &listen_addr, int port, size_t cache_size, int min_ttl, int max_ttl, const ServerEndpoint &upstream, const std::string &proxy = "", int mgmt_port = 953);

    void start();

private:
    std::string listen_addr_;
    int port_;
    DnsCache cache_;
    ServerEndpoint upstream_;
    std::string proxy_;
    int mgmt_port_;

    void handle_udp(int udp_sock);

    void handle_tcp(int tcp_sock);

    void handle_management(int mgmt_sock, std::atomic<bool>& running);

    DnsResponse resolve_upstream(const std::string &domain, uint16_t qtype);

    void process_query(const unsigned char *query, int query_len, unsigned char *response, int *response_len, const std::string &client_ip);

    // void cache_management_loop(std::atomic<bool> &running);

    std::string process_management_command(const std::string &cmd);

    std::string current_time_str() const;
};

#endif //DNS_QUERY_DNS_SERVER_H
