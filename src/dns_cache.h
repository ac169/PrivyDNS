#ifndef DNS_QUERY_DNS_CACHE_H
#define DNS_QUERY_DNS_CACHE_H

#include <string>
#include <unordered_map>
#include <list>
#include <ctime>
#include "dns_packet.h"

class DnsCache {
public:
    DnsCache(size_t max_size = 250, int min_ttl = 0, int max_ttl = 86400);

    bool get(const std::string &domain, uint16_t qtype, DnsResponse &response);

    void put(const std::string &domain, uint16_t qtype, const DnsResponse &response, int ttl_override = -1);

    bool remove(const std::string &domain, uint16_t qtype);

    void clear();

    std::vector<std::string> list() const; // return list of entries as strings
    size_t size() const { return cache_map_.size(); }

private:
    struct Entry {
        std::string domain;
        uint16_t qtype;
        DnsResponse response;
        time_t expire_at;
    };

    std::list<std::string> lru_list_; // list of keys in LRU order (most recent at front)
    std::unordered_map<std::string, Entry> cache_map_;
    size_t max_size_;
    int min_ttl_;
    int max_ttl_;

    std::string make_key(const std::string &domain, uint16_t qtype) const;

    void touch(const std::string &key);

    void evict_if_needed();

    int clamp_ttl(int ttl) const;
};

#endif //DNS_QUERY_DNS_CACHE_H
