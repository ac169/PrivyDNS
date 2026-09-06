#ifndef DNS_QUERY_DNS_PACKET_H
#define DNS_QUERY_DNS_PACKET_H

#include <string>
#include <vector>
#include <cstdint>

struct DnsQuestion {
    std::string name;
    uint16_t qtype;
    uint16_t qclass;
};

struct DnsRecord {
    std::string name;
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    std::string rdata_str;
};

struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    bool qr, aa, tc, rd, ra;
    uint8_t opcode;
    uint8_t rcode;
};

struct DnsResponse {
    bool valid = false;
    DnsHeader header;
    std::vector<DnsQuestion> questions;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authorities;
    std::vector<DnsRecord> additionals;
    std::string server_info;
};

struct ServerEndpoint {
    std::string protocol; /* udp, https, tls */
    std::string host;
    int port;
    std::string path;     /* Used for DoH, e.g., /dns-query */
};

std::string qtype_to_str(uint16_t qtype);

uint16_t str_to_qtype(const std::string &str);

int build_dns_packet(const std::string &domain, uint16_t qtype, unsigned char *packet, int max_len);

int skip_name(const unsigned char *buffer, int pos, int len);

void parse_dns_response(const unsigned char *buffer, int len);

ServerEndpoint parse_server_string(const std::string &input);

bool parse_proxy_string(const std::string &input, std::string &type, std::string &host, int &port);

bool parse_dnscrypt_stamp(const std::string& stamp_str, std::string& out_ip, int& out_port, std::vector<unsigned char>& out_pk, std::string& out_provider);

void parse_dns_response_to_struct(const unsigned char *buffer, int len, DnsResponse &resp);

void print_dns_response(const DnsResponse &resp);

void print_dns_responses(const std::vector<DnsResponse> &responses);

int parse_dns_query(const unsigned char *buffer, int len, std::string &domain, uint16_t &qtype);

int build_dns_response(const DnsResponse &resp, unsigned char *buffer, int max_len);

#endif //DNS_QUERY_DNS_PACKET_H
