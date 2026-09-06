#ifndef DNS_QUERY_DNS_SERVICES_H
#define DNS_QUERY_DNS_SERVICES_H

#include <string>
#include <cstdint>
#include "dns_packet.h"

DnsResponse query_udp(const std::string &domain, uint16_t qtype, const ServerEndpoint &ep, const std::string &proxy);

DnsResponse query_dot(const std::string &domain, uint16_t qtype, const ServerEndpoint &ep, const std::string &proxy);

DnsResponse query_doh(const std::string &domain, uint16_t qtype, const ServerEndpoint &ep, const std::string &proxy);

#endif //DNS_QUERY_DNS_SERVICES_H
