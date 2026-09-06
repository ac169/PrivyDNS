#include "dns_cache.h"
#include <algorithm>
#include <sstream>

DnsCache::DnsCache(size_t max_size, int min_ttl, int max_ttl) : max_size_(max_size), min_ttl_(min_ttl), max_ttl_(max_ttl) {}

std::string DnsCache::make_key(const std::string &domain, uint16_t qtype) const {
    return domain + "|" + std::to_string(qtype);
}

void DnsCache::touch(const std::string &key) {
    auto it = std::find(lru_list_.begin(), lru_list_.end(), key);
    if (it != lru_list_.end()) {
        lru_list_.erase(it);
    }
    lru_list_.push_front(key);
}

void DnsCache::evict_if_needed() {
    while (cache_map_.size() > max_size_ && !lru_list_.empty()) {
        std::string evict_key = lru_list_.back();
        lru_list_.pop_back();
        cache_map_.erase(evict_key);
    }
}

int DnsCache::clamp_ttl(int ttl) const {
    if (ttl < min_ttl_) return min_ttl_;
    if (ttl > max_ttl_) return max_ttl_;
    return ttl;
}

bool DnsCache::get(const std::string &domain, uint16_t qtype, DnsResponse &response) {
    std::string key = make_key(domain, qtype);
    auto it = cache_map_.find(key);
    if (it == cache_map_.end()) return false;

    time_t now = time(nullptr);
    if (it->second.expire_at <= now) {
        // expired, remove
        cache_map_.erase(it);
        lru_list_.remove(key);
        return false;
    }

    // Adjust TTL in response
    response = it->second.response;
    time_t remaining = it->second.expire_at - now;
    for (auto &rec: response.answers) {
        if (rec.ttl > remaining) rec.ttl = (uint32_t) remaining;
    }
    for (auto &rec: response.authorities) {
        if (rec.ttl > remaining) rec.ttl = (uint32_t) remaining;
    }
    for (auto &rec: response.additionals) {
        if (rec.ttl > remaining) rec.ttl = (uint32_t) remaining;
    }

    touch(key);
    return true;
}

void DnsCache::put(const std::string &domain, uint16_t qtype, const DnsResponse &response, int ttl_override) {
    std::string key = make_key(domain, qtype);
    Entry entry;
    entry.domain = domain;
    entry.qtype = qtype;
    entry.response = response;

    int ttl = ttl_override;
    if (ttl < 0) {
        // derive TTL from first answer (or use max_ttl_)
        if (!response.answers.empty()) {
            ttl = (int) response.answers[0].ttl;
        } else {
            ttl = 60; // default
        }
    }
    ttl = clamp_ttl(ttl);
    entry.expire_at = time(nullptr) + ttl;

    if (cache_map_.find(key) != cache_map_.end()) {
        cache_map_[key] = entry;
        touch(key);
    } else {
        cache_map_[key] = entry;
        lru_list_.push_front(key);
        evict_if_needed();
    }
}

bool DnsCache::remove(const std::string &domain, uint16_t qtype) {
    std::string key = make_key(domain, qtype);
    auto it = cache_map_.find(key);
    if (it == cache_map_.end()) return false;
    cache_map_.erase(it);
    lru_list_.remove(key);
    return true;
}

void DnsCache::clear() {
    cache_map_.clear();
    lru_list_.clear();
}

std::vector<std::string> DnsCache::list() const {
    std::vector<std::string> result;
    time_t now = time(nullptr);
    for (const auto &kv: cache_map_) {
        const Entry &entry = kv.second;
        std::ostringstream oss;
        // 域名和类型
        oss << entry.domain << " " << qtype_to_str(entry.qtype) << " ";

        // 提取答案记录中的 rdata_str(IP 或域名)
        bool first = true;
        for (const auto &rec: entry.response.answers) {
            if (!first) oss << ", ";
            oss << rec.rdata_str;
            first = false;
        }
        if (first) {
            oss << "(no answers)";
        }

        // 剩余时间处理
        long seconds_left = (long) (entry.expire_at - now);
        if (seconds_left <= 0) {
            oss << " [expired]";
        } else {
            oss << " [expires in " << seconds_left << "s]";
        }
        result.push_back(oss.str());
    }

    return result;
}
