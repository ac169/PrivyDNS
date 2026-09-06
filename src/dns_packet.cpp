#include "dns_packet.h"
#include <iostream>
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#define strncasecmp _strnicmp
#else
#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#endif

std::string qtype_to_str(uint16_t qtype) {
    if (qtype == 0x0001) return "A";
    if (qtype == 0x001C) return "AAAA";
    if (qtype == 0x0005) return "CNAME";
    if (qtype == 0x0002) return "NS";
    if (qtype == 0x0010) return "TXT";
    if (qtype == 0x000F) return "MX";
    return "TYPE" + std::to_string(qtype);
}

uint16_t str_to_qtype(const std::string &str) {
    if (str == "A" || str == "a") return 0x0001;
    if (str == "AAAA" || str == "aaaa") return 0x001C;
    if (str == "CNAME" || str == "cname") return 0x0005;
    if (str == "NS" || str == "ns") return 0x0002;
    if (str == "TXT" || str == "txt") return 0x0010;
    if (str == "MX" || str == "mx") return 0x000F;
    return 0x0001; /* Fallback to A */
}

int build_dns_packet(const std::string &domain, uint16_t qtype, unsigned char *packet, int max_len) {
    if (max_len < 12) return -1;
    packet[0] = 0x12;
    packet[1] = 0x34; /* ID */
    packet[2] = 0x01;
    packet[3] = 0x00; /* Flags: RD=1 */
    packet[4] = 0x00;
    packet[5] = 0x01; /* QDCOUNT: 1 */
    packet[6] = 0x00;
    packet[7] = 0x00; /* ANCOUNT: 0 */
    packet[8] = 0x00;
    packet[9] = 0x00; /* NSCOUNT: 0 */
    packet[10] = 0x00;
    packet[11] = 0x00; /* ARCOUNT: 0 */

    int pos = 12;
    size_t start = 0;
    size_t end;

    while ((end = domain.find('.', start)) != std::string::npos) {
        int len = (int) (end - start);
        if (pos + 1 + len > max_len) return -1;
        packet[pos++] = (unsigned char) len;
        memcpy(&packet[pos], domain.c_str() + start, len);
        pos += len;
        start = end + 1;
    }

    int len = (int) (domain.length() - start);
    if (pos + 1 + len + 4 > max_len) return -1;
    packet[pos++] = (unsigned char) len;
    memcpy(&packet[pos], domain.c_str() + start, len);
    pos += len;
    packet[pos++] = 0x00; /* Label End */

    packet[pos++] = (qtype >> 8) & 0xFF;
    packet[pos++] = qtype & 0xFF;
    packet[pos++] = 0x00;
    packet[pos++] = 0x01; /* QCLASS: IN */
    return pos;
}

int skip_name(const unsigned char *buffer, int pos, int len) {
    if (pos >= len) return -1;
    while (1) {
        if (pos >= len) return -1;
        unsigned char c = buffer[pos];
        if ((c & 0xC0) == 0xC0) return pos + 2;
        else if (c == 0x00) return pos + 1;
        else pos += (c + 1);
    }
}

static int read_name(const unsigned char *buffer, int len, int pos, std::string &name) {
    if (pos >= len) return -1;
    name.clear();
    int jumped = 0;
    int next_pos = -1;
    bool first = true;
    while (true) {
        if (pos >= len) return -1;
        unsigned char c = buffer[pos];
        if ((c & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return -1;
            int offset = ((c & 0x3F) << 8) | buffer[pos + 1];
            if (offset >= len) return -1;
            if (next_pos < 0) next_pos = pos + 2;
            pos = offset;
            jumped++;
            if (jumped > 20) return -1; // 防止循环
        } else if (c == 0x00) {
            if (next_pos < 0) next_pos = pos + 1;
            return next_pos;
        } else {
            if (pos + 1 + c > len) return -1;
            if (!first) name += '.';
            name.append((const char *) &buffer[pos + 1], c);
            pos += c + 1;
            first = false;
        }
    }
}

static std::string format_rdata(uint16_t type, const unsigned char *rdata, int rdlen, const unsigned char *full_buffer, int full_len) {
    std::string out;
    switch (type) {
        case 0x0001: { // A
            if (rdlen == 4) {
                char buf[64];
                snprintf(buf, sizeof(buf), "%u.%u.%u.%u", rdata[0], rdata[1], rdata[2], rdata[3]);
                out = buf;
            } else {
                out = "(invalid A record)";
            }
            break;
        }
        case 0x001C: { // AAAA
            if (rdlen == 16) {
                char buf[128];
                int pos = 0;
                for (int i = 0; i < 16; i += 2) {
                    if (i > 0) buf[pos++] = ':';
                    pos += sprintf(buf + pos, "%02x%02x", rdata[i], rdata[i + 1]);
                }
                buf[pos] = '\0';
                out = buf;
            } else {
                out = "(invalid AAAA record)";
            }
            break;
        }
        case 0x0005: { // CNAME
            std::string name;
            if (read_name(full_buffer, full_len, (int) (rdata - full_buffer), name) >= 0) {
                out = name;
            } else {
                out = "(invalid CNAME)";
            }
            break;
        }
        case 0x0002: { // NS
            std::string name;
            if (read_name(full_buffer, full_len, (int) (rdata - full_buffer), name) >= 0) {
                out = name;
            } else {
                out = "(invalid NS)";
            }
            break;
        }
        case 0x000F: { // MX
            if (rdlen >= 2) {
                int pref = (rdata[0] << 8) | rdata[1];
                std::string mx;
                if (read_name(full_buffer, full_len, (int) (rdata + 2 - full_buffer), mx) >= 0) {
                    out = std::to_string(pref) + " " + mx;
                } else {
                    out = "(invalid MX)";
                }
            } else {
                out = "(invalid MX)";
            }
            break;
        }
        case 0x0010: { // TXT
            if (rdlen >= 1) {
                int pos = 0;
                bool first_part = true;
                while (pos < rdlen) {
                    int part_len = rdata[pos];
                    pos++;
                    if (pos + part_len > rdlen) {
                        out = "(invalid TXT)";
                        break;
                    }
                    if (!first_part) out += " ";
                    out += std::string((const char *) rdata + pos, part_len);
                    pos += part_len;
                    first_part = false;
                }
            } else {
                out = "(empty TXT)";
            }
            break;
        }
        case 0x0006: { // SOA（简化）
            out = "(SOA record not fully parsed)";
            break;
        }
        case 0x000C: { // PTR
            std::string name;
            if (read_name(full_buffer, full_len, (int) (rdata - full_buffer), name) >= 0) {
                out = name;
            } else {
                out = "(invalid PTR)";
            }
            break;
        }
        default: {
            out = "\\# " + std::to_string(rdlen) + " ";
            for (int i = 0; i < rdlen; ++i) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02x", rdata[i]);
                out += buf;
            }
            break;
        }
    }
    return out;
}

static std::string rcode_to_str(uint8_t rcode) {
    switch (rcode) {
        case 0:
            return "NOERROR";
        case 1:
            return "FORMERR";
        case 2:
            return "SERVFAIL";
        case 3:
            return "NXDOMAIN";
        case 4:
            return "NOTIMP";
        case 5:
            return "REFUSED";
        default:
            return "UNKNOWN";
    }
}

static std::string opcode_to_str(uint8_t opcode) {
    switch (opcode) {
        case 0:
            return "QUERY";
        case 1:
            return "IQUERY";
        case 2:
            return "STATUS";
        default:
            return "OPCODE" + std::to_string(opcode);
    }
}

//void parse_dns_response(const unsigned char *buffer, int len) {
//    if (len < 12) {
//        std::cout << "  Error: Packet too short.\n";
//        return;
//    }
//
//    uint16_t id = (buffer[0] << 8) | buffer[1];
//    uint16_t flags = (buffer[2] << 8) | buffer[3];
//    uint16_t qdcount = (buffer[4] << 8) | buffer[5];
//    uint16_t ancount = (buffer[6] << 8) | buffer[7];
//    uint16_t nscount = (buffer[8] << 8) | buffer[9];
//    uint16_t arcount = (buffer[10] << 8) | buffer[11];
//
//    bool qr = (flags & 0x8000) != 0;
//    unsigned char opcode = (flags >> 11) & 0x0F;
//    bool aa = (flags & 0x0400) != 0;
//    bool tc = (flags & 0x0200) != 0;
//    bool rd = (flags & 0x0100) != 0;
//    bool ra = (flags & 0x0080) != 0;
//    unsigned char rcode = flags & 0x0F;
//
//    std::string status;
//    switch (rcode) {
//        case 0:
//            status = "NOERROR";
//            break;
//        case 1:
//            status = "FORMERR";
//            break;
//        case 2:
//            status = "SERVFAIL";
//            break;
//        case 3:
//            status = "NXDOMAIN";
//            break;
//        case 4:
//            status = "NOTIMP";
//            break;
//        case 5:
//            status = "REFUSED";
//            break;
//        default:
//            status = "UNKNOWN";
//            break;
//    }
//
//    std::string opcode_str;
//    switch (opcode) {
//        case 0:
//            opcode_str = "QUERY";
//            break;
//        case 1:
//            opcode_str = "IQUERY";
//            break;
//        case 2:
//            opcode_str = "STATUS";
//            break;
//        default:
//            opcode_str = "OPCODE" + std::to_string(opcode);
//            break;
//    }
//
//    std::cout << ";; ->>HEADER<<- opcode: " << opcode_str << ", status: " << status << ", id: " << id << "\n";
//    std::cout << ";; flags:";
//    if (qr) std::cout << " qr";
//    if (aa) std::cout << " aa";
//    if (tc) std::cout << " tc";
//    if (rd) std::cout << " rd";
//    if (ra) std::cout << " ra";
//    std::cout << "; QUERY: " << qdcount << ", ANSWER: " << ancount << ", AUTHORITY: " << nscount << ", ADDITIONAL: " << arcount << "\n";
//
//    int pos = 12;
//
//    if (qdcount > 0) {
//        std::cout << "\n;; QUESTION SECTION:\n";
//        for (int i = 0; i < qdcount; i++) {
//            std::string qname;
//            pos = read_name(buffer, len, pos, qname);
//            if (pos < 0 || pos + 4 > len) {
//                std::cout << "  (truncated question)\n";
//                return;
//            }
//            uint16_t qtype = (buffer[pos] << 8) | buffer[pos + 1];
//            uint16_t qclass = (buffer[pos + 2] << 8) | buffer[pos + 3];
//            pos += 4;
//            std::cout << ";" << qname << "\t\t\tIN\t" << qtype_to_str(qtype) << "\n";
//        }
//    }
//
//    auto print_rr_section = [&](int count, const char *section_name) {
//        if (count > 0) {
//            std::cout << "\n;; " << section_name << ":\n";
//            for (int i = 0; i < count; i++) {
//                std::string owner;
//                pos = read_name(buffer, len, pos, owner);
//                if (pos < 0 || pos + 10 > len) {
//                    std::cout << "  (truncated record)\n";
//                    return;
//                }
//                uint16_t type = (buffer[pos] << 8) | buffer[pos + 1];
//                uint16_t rclass = (buffer[pos + 2] << 8) | buffer[pos + 3];
//                uint32_t ttl = ((uint32_t) buffer[pos + 4] << 24) | ((uint32_t) buffer[pos + 5] << 16) | ((uint32_t) buffer[pos + 6] << 8) | buffer[pos + 7];
//                uint16_t rdlen = (buffer[pos + 8] << 8) | buffer[pos + 9];
//                pos += 10;
//                if (pos + rdlen > len) {
//                    std::cout << "  (truncated rdata)\n";
//                    return;
//                }
//                const unsigned char *rdata = buffer + pos;
//                std::string rdata_str = format_rdata(type, rdata, rdlen, buffer, len);
//                std::string type_str = qtype_to_str(type);
//                // 对齐输出（模拟 dig 风格）
//                std::cout << owner << "\t" << ttl << "\tIN\t" << type_str << "\t" << rdata_str << "\n";
//                pos += rdlen;
//            }
//        }
//    };
//
//    // 应答段
//    print_rr_section(ancount, "ANSWER SECTION");
//    // 权威段
//    print_rr_section(nscount, "AUTHORITY SECTION");
//    // 附加段
//    print_rr_section(arcount, "ADDITIONAL SECTION");
//
//    std::cout << std::endl; // 额外换行
//}

static std::string get_system_dns_server() {
#ifdef _WIN32
    FIXED_INFO *pFixedInfo = nullptr;
    ULONG ulOutBufLen = sizeof(FIXED_INFO);
    pFixedInfo = (FIXED_INFO *) malloc(ulOutBufLen);
    if (!pFixedInfo) return "";

    DWORD dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pFixedInfo);
        pFixedInfo = (FIXED_INFO *) malloc(ulOutBufLen);
        if (!pFixedInfo) return "";
        dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen);
    }

    std::string result;
    if (dwRetVal == NO_ERROR) {
        IP_ADDR_STRING *pDnsServer = &(pFixedInfo->DnsServerList);
        if (pDnsServer && pDnsServer->IpAddress.String[0] != '\0') {
            result = pDnsServer->IpAddress.String;
        }
    }

    free(pFixedInfo);

    return result;
#else
    // Linux / macOS: 解析 /etc/resolv.conf
    std::ifstream file("/etc/resolv.conf");
    std::string line;

    while (std::getline(file, line)) {
        if (line.rfind("nameserver", 0) == 0) {
            std::istringstream iss(line);
            std::string keyword, ip;
            iss >> keyword >> ip;
            if (!ip.empty()) return ip;
        }
    }

    return "";
#endif
}

ServerEndpoint parse_server_string(const std::string &input) {
    ServerEndpoint ep = {"udp", "", 53, ""};

    if (input.empty()) {
        std::string sys_dns = get_system_dns_server();

        if (!sys_dns.empty()) {
            ep.host = sys_dns;
        } else {
            ep.host = "114.114.114.114";   // 回退
        }

        return ep;
    }

    size_t proto_end = input.find("://");
    std::string remaining = input;
    if (proto_end != std::string::npos) {
        ep.protocol = input.substr(0, proto_end);
        remaining = input.substr(proto_end + 3);
    } else {
        ep.protocol = "udp";
    }

    size_t path_start = remaining.find('/');
    if (path_start != std::string::npos) {
        ep.path = remaining.substr(path_start);
        remaining = remaining.substr(0, path_start);
    }

    size_t colon = remaining.find(':');
    if (colon != std::string::npos) {
        ep.host = remaining.substr(0, colon);
        ep.port = std::stoi(remaining.substr(colon + 1));
    } else {
        ep.host = remaining;
        if (ep.protocol == "https") ep.port = 443;
        else if (ep.protocol == "tls") ep.port = 853;
        else ep.port = 53;
    }

    return ep;
}

bool parse_proxy_string(const std::string &input, std::string &type, std::string &host, int &port) {
    if (input.empty()) return false;
    size_t sep = input.find("://");
    if (sep == std::string::npos) return false;
    type = input.substr(0, sep);
    std::string rem = input.substr(sep + 3);
    size_t colon = rem.find(':');
    if (colon == std::string::npos) return false;
    host = rem.substr(0, colon);
    port = std::stoi(rem.substr(colon + 1));
    return true;
}

bool decode_base64url(const std::string &input, std::vector<unsigned char> &out) {
    std::string b64 = "";
    for (size_t i = 0; i < input.length(); i++) {
        if (input[i] == '-') b64.push_back('+');
        else if (input[i] == '_') b64.push_back('/');
        else if (input[i] != '=' && input[i] != '\r' && input[i] != '\n' && input[i] != ' ') {
            b64.push_back(input[i]);
        }
    }
    while (b64.length() % 4) {
        b64.push_back('=');
    }

    static const int Tbl[] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                              -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                              22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1};

    int val = 0, valb = -8;
    for (size_t i = 0; i < b64.length(); i++) {
        unsigned char c = b64[i];
        if (c == '=') break;
        if (c >= 128 || Tbl[c] == -1) return false;
        val = (val << 6) + Tbl[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return !out.empty();
}

bool parse_dnscrypt_stamp(const std::string &stamp_str, std::string &out_ip, int &out_port, std::vector<unsigned char> &out_pk, std::string &out_provider) {
    if (stamp_str.substr(0, 7) != "sdns://") return false;
    std::vector<unsigned char> raw_bytes;
    if (!decode_base64url(stamp_str.substr(7), raw_bytes)) return false;

    if (raw_bytes.size() < 10) return false;

    /* Verify RFC Stamp Protocol ID (0x01 = DNSCrypt) */
    if (raw_bytes[0] != 0x01) {
        std::cerr << "Diagnostic Type Mismatch: Stamp Protocol ID is 0x" << std::hex << (int) raw_bytes[0] << std::dec;
        if (raw_bytes[0] == 0x03) std::cerr << " (DoT)";
        else if (raw_bytes[0] == 0x02) std::cerr << " (DoH)";
        std::cerr << "]. This program strictly requires a true 0x01 (DNSCrypt) server stamp.\n";
        return false;
    }

    /* Start track cursor: Skip ID(1B) + Properties(8B) */
    size_t pos = 9;

    /* 1. Extract IP Address Block */
    size_t ip_len = raw_bytes[pos++];
    if (pos + ip_len > raw_bytes.size()) return false;
    std::string addr((char *) &raw_bytes[pos], ip_len);
    pos += ip_len;

    size_t colon = addr.find(':');
    if (colon != std::string::npos) {
        out_ip = addr.substr(0, colon);
        out_port = std::stoi(addr.substr(colon + 1));
    } else {
        out_ip = addr;
        out_port = 443;
    }

    /* 2. Extract 32-byte Public Key Matrix (Handles internal 0x00 padding separator safely) */
    if (pos < raw_bytes.size() && (raw_bytes[pos] == 0x00 || raw_bytes[pos] == 0x20)) {
        pos++; /* Advance cursor past the RFC-compliant isolation pad byte */
    }

    if (pos + 32 > raw_bytes.size()) return false;
    out_pk.assign(raw_bytes.begin() + pos, raw_bytes.begin() + pos + 32);
    pos += 32;

    /* 3. Extract Provider Hostname String */
    if (pos >= raw_bytes.size()) return false;
    size_t prov_len = raw_bytes[pos++];
    if (pos + prov_len > raw_bytes.size()) return false;

    out_provider.assign((char *) &raw_bytes[pos], prov_len);
    return true;
}

void parse_dns_response_to_struct(const unsigned char *buffer, int len, DnsResponse &resp) {
    resp = DnsResponse();
    if (len < 12) {
        return;
    }

    resp.header.id = (buffer[0] << 8) | buffer[1];
    resp.header.flags = (buffer[2] << 8) | buffer[3];
    resp.header.qdcount = (buffer[4] << 8) | buffer[5];
    resp.header.ancount = (buffer[6] << 8) | buffer[7];
    resp.header.nscount = (buffer[8] << 8) | buffer[9];
    resp.header.arcount = (buffer[10] << 8) | buffer[11];

    resp.header.qr = (resp.header.flags & 0x8000) != 0;
    resp.header.opcode = (resp.header.flags >> 11) & 0x0F;
    resp.header.aa = (resp.header.flags & 0x0400) != 0;
    resp.header.tc = (resp.header.flags & 0x0200) != 0;
    resp.header.rd = (resp.header.flags & 0x0100) != 0;
    resp.header.ra = (resp.header.flags & 0x0080) != 0;
    resp.header.rcode = resp.header.flags & 0x0F;

    int pos = 12;

    for (int i = 0; i < resp.header.qdcount; i++) {
        DnsQuestion q;
        pos = read_name(buffer, len, pos, q.name);
        if (pos < 0 || pos + 4 > len) return;
        q.qtype = (buffer[pos] << 8) | buffer[pos + 1];
        q.qclass = (buffer[pos + 2] << 8) | buffer[pos + 3];
        pos += 4;
        resp.questions.push_back(q);
    }

    auto parse_rr_section = [&](int count, std::vector<DnsRecord> &section) {
        for (int i = 0; i < count; i++) {
            DnsRecord rec;
            pos = read_name(buffer, len, pos, rec.name);
            if (pos < 0 || pos + 10 > len) return;
            rec.type = (buffer[pos] << 8) | buffer[pos + 1];
            rec.rclass = (buffer[pos + 2] << 8) | buffer[pos + 3];
            rec.ttl = ((uint32_t) buffer[pos + 4] << 24) | ((uint32_t) buffer[pos + 5] << 16) | ((uint32_t) buffer[pos + 6] << 8) | buffer[pos + 7];
            uint16_t rdlen = (buffer[pos + 8] << 8) | buffer[pos + 9];
            pos += 10;
            if (pos + rdlen > len) return;
            const unsigned char *rdata = buffer + pos;
            rec.rdata_str = format_rdata(rec.type, rdata, rdlen, buffer, len);
            section.push_back(rec);
            pos += rdlen;
        }
    };

    parse_rr_section(resp.header.ancount, resp.answers);
    parse_rr_section(resp.header.nscount, resp.authorities);
    parse_rr_section(resp.header.arcount, resp.additionals);

    resp.valid = true;
}

//void print_dns_response(const DnsResponse &resp) {
//    if (!resp.valid) {
//        std::cout << "  Error: invalid DNS response.\n";
//        return;
//    }
//
//    std::cout << ";; ->>HEADER<<- opcode: " << opcode_to_str(resp.header.opcode) << ", status: " << rcode_to_str(resp.header.rcode) << ", id: " << resp.header.id << "\n";
//    std::cout << ";; flags:";
//    if (resp.header.qr) std::cout << " qr";
//    if (resp.header.aa) std::cout << " aa";
//    if (resp.header.tc) std::cout << " tc";
//    if (resp.header.rd) std::cout << " rd";
//    if (resp.header.ra) std::cout << " ra";
//    std::cout << "; QUERY: " << resp.header.qdcount << ", ANSWER: " << resp.header.ancount << ", AUTHORITY: " << resp.header.nscount << ", ADDITIONAL: " << resp.header.arcount << "\n";
//
//    if (!resp.questions.empty()) {
//        std::cout << "\n;; QUESTION SECTION:\n";
//        for (const auto &q: resp.questions) {
//            std::cout << ";" << q.name << "\t\t\tIN\t" << qtype_to_str(q.qtype) << "\n";
//        }
//    }
//
//    auto print_rr = [](const std::vector<DnsRecord> &records, const char *title) {
//        if (!records.empty()) {
//            std::cout << "\n;; " << title << ":\n";
//            for (const auto &rec: records) {
//                std::cout << rec.name << "\t" << rec.ttl << "\tIN\t" << qtype_to_str(rec.type) << "\t" << rec.rdata_str << "\n";
//            }
//        }
//    };
//
//    print_rr(resp.answers, "ANSWER SECTION");
//    print_rr(resp.authorities, "AUTHORITY SECTION");
//    print_rr(resp.additionals, "ADDITIONAL SECTION");
//
//    std::cout << std::endl;
//}
//
//void print_dns_responses(const std::vector<DnsResponse> &responses) {
//    if (responses.empty()) return;
//
//    const DnsResponse &first = responses[0];
//    if (first.valid) {
//        std::cout << ";; ->>HEADER<<- opcode: " << opcode_to_str(first.header.opcode) << ", status: " << rcode_to_str(first.header.rcode) << ", id: " << first.header.id << "\n";
//        std::cout << ";; flags:";
//        if (first.header.qr) std::cout << " qr";
//        if (first.header.aa) std::cout << " aa";
//        if (first.header.tc) std::cout << " tc";
//        if (first.header.rd) std::cout << " rd";
//        if (first.header.ra) std::cout << " ra";
//        std::cout << "; QUERY: " << first.header.qdcount << ", ANSWER: " << first.header.ancount + (responses.size() > 1 ? responses[1].header.ancount : 0) << ", AUTHORITY: "
//                  << first.header.nscount + (responses.size() > 1 ? responses[1].header.nscount : 0) << ", ADDITIONAL: "
//                  << first.header.arcount + (responses.size() > 1 ? responses[1].header.arcount : 0) << "\n";
//
//        if (!first.questions.empty()) {
//            std::cout << "\n;; QUESTION SECTION:\n";
//            for (const auto &q: first.questions) {
//                std::cout << ";" << q.name << "\t\t\tIN\t" << qtype_to_str(q.qtype) << "\n";
//            }
//        }
//    } else {
//        std::cout << ";; Query failed or received no response.\n";
//        return;
//    }
//
//    std::vector<DnsRecord> all_answers, all_auth, all_add;
//    for (const auto &resp: responses) {
//        if (resp.valid) {
//            all_answers.insert(all_answers.end(), resp.answers.begin(), resp.answers.end());
//            all_auth.insert(all_auth.end(), resp.authorities.begin(), resp.authorities.end());
//            all_add.insert(all_add.end(), resp.additionals.begin(), resp.additionals.end());
//        }
//    }
//
//    auto print_rr = [](const std::vector<DnsRecord> &records, const char *title) {
//        if (!records.empty()) {
//            std::cout << "\n;; " << title << ":\n";
//            for (const auto &rec: records) {
//                std::cout << rec.name << "\t" << rec.ttl << "\tIN\t" << qtype_to_str(rec.type) << "\t" << rec.rdata_str << "\n";
//            }
//        }
//    };
//
//    print_rr(all_answers, "ANSWER SECTION");
//    print_rr(all_auth, "AUTHORITY SECTION");
//    print_rr(all_add, "ADDITIONAL SECTION");
//
//    std::cout << std::endl;
//}

void parse_dns_response(const unsigned char *buffer, int len) {
    DnsResponse resp;
    parse_dns_response_to_struct(buffer, len, resp);
    print_dns_response(resp);
}

void print_dns_response(const DnsResponse &resp) {
    if (!resp.valid) return;

    // Print question section
    if (!resp.questions.empty()) {
        std::cout << "\n;; QUESTION SECTION:\n";
        for (const auto &q: resp.questions) {
            std::cout << ";" << q.name << "\t\t\tIN\t" << qtype_to_str(q.qtype) << "\n";
        }
    }

    // Print answer section header
    if (!resp.answers.empty()) {
        std::cout << "\n;; ANSWER SECTION:\n";
        for (const auto &rec: resp.answers) {
            std::cout << rec.name << "\t" << rec.ttl << "\tIN\t" << qtype_to_str(rec.type) << "\t" << rec.rdata_str << "\n";
        }
    }

    // Add a blank line after the response for separation
    std::cout << "\n";

    if (!resp.server_info.empty()) {
        std::cout << ";; SERVER: " << resp.server_info << "\n";
    }

    std::cout << "\n\n";
}

void print_dns_responses(const std::vector<DnsResponse> &responses) {
    for (const auto &resp: responses) {
        print_dns_response(resp);
    }
}

int parse_dns_query(const unsigned char *buffer, int len, std::string &domain, uint16_t &qtype) {
    if (len < 12) return -1;
    int pos = 12;
    // Skip question name
    pos = read_name(buffer, len, pos, domain);   // uses existing static read_name
    if (pos < 0 || pos + 4 > len) return -1;
    qtype = (buffer[pos] << 8) | buffer[pos + 1];
    // We don't need qclass, skip
    return 0;
}

//int build_dns_response(const DnsResponse &resp, unsigned char *buffer, int max_len) {
//    if (!resp.valid || max_len < 12) return -1;
//
//    // Header
//    buffer[0] = (resp.header.id >> 8) & 0xFF;
//    buffer[1] = resp.header.id & 0xFF;
//    uint16_t flags = 0;
//    if (resp.header.qr) flags |= 0x8000;
//    flags |= (resp.header.opcode & 0x0F) << 11;
//    if (resp.header.aa) flags |= 0x0400;
//    if (resp.header.tc) flags |= 0x0200;
//    if (resp.header.rd) flags |= 0x0100;
//    if (resp.header.ra) flags |= 0x0080;
//    flags |= (resp.header.rcode & 0x0F);
//    buffer[2] = (flags >> 8) & 0xFF;
//    buffer[3] = flags & 0xFF;
//
//    buffer[4] = (resp.header.qdcount >> 8) & 0xFF;
//    buffer[5] = resp.header.qdcount & 0xFF;
//    buffer[6] = (resp.header.ancount >> 8) & 0xFF;
//    buffer[7] = resp.header.ancount & 0xFF;
//    buffer[8] = (resp.header.nscount >> 8) & 0xFF;
//    buffer[9] = resp.header.nscount & 0xFF;
//    buffer[10] = (resp.header.arcount >> 8) & 0xFF;
//    buffer[11] = resp.header.arcount & 0xFF;
//
//    int pos = 12;
//
//    // Write question section (we assume questions are already stored as names)
//    for (const auto &q: resp.questions) {
//        // Encode name (simple, no compression)
//        size_t start = 0, end;
//        std::string name = q.name;
//        if (!name.empty() && name.back() == '.') name.pop_back(); // remove trailing dot if present
//        while ((end = name.find('.', start)) != std::string::npos) {
//            int label_len = end - start;
//            if (pos + 1 + label_len > max_len) return -1;
//            buffer[pos++] = (unsigned char) label_len;
//            memcpy(buffer + pos, name.c_str() + start, label_len);
//            pos += label_len;
//            start = end + 1;
//        }
//        int last_len = name.length() - start;
//        if (pos + 1 + last_len + 4 > max_len) return -1;
//        buffer[pos++] = (unsigned char) last_len;
//        memcpy(buffer + pos, name.c_str() + start, last_len);
//        pos += last_len;
//        buffer[pos++] = 0; // terminating zero length label
//
//        buffer[pos++] = (q.qtype >> 8) & 0xFF;
//        buffer[pos++] = q.qtype & 0xFF;
//        buffer[pos++] = 0; // class IN
//        buffer[pos++] = 1;
//    }
//
//    // Write resource records (simplified: write answer records using rdata_str, ignoring original raw rdata)
//    // This assumes rdata_str contains a presentation format that can be parsed back; better to store raw rdata.
//    // For the purpose of this server, we can reconstruct from stored data (e.g., A, AAAA, CNAME, etc.)
//    // We will implement basic type support matching our client's parse.
//    auto write_rr = [&](const DnsRecord &rec) -> bool {
//        // Write name (no compression)
//        std::string name = rec.name;
//        if (!name.empty() && name.back() == '.') name.pop_back();
//        size_t start = 0, end;
//        while ((end = name.find('.', start)) != std::string::npos) {
//            int label_len = end - start;
//            if (pos + 1 + label_len > max_len) return false;
//            buffer[pos++] = (unsigned char) label_len;
//            memcpy(buffer + pos, name.c_str() + start, label_len);
//            pos += label_len;
//            start = end + 1;
//        }
//        int last_len = name.length() - start;
//        if (pos + 1 + last_len + 10 > max_len) return false;
//        buffer[pos++] = (unsigned char) last_len;
//        memcpy(buffer + pos, name.c_str() + start, last_len);
//        pos += last_len;
//        buffer[pos++] = 0;
//
//        // Type, class, TTL, RDLENGTH placeholder
//        if (pos + 10 > max_len) return false;
//        buffer[pos++] = (rec.type >> 8) & 0xFF;
//        buffer[pos++] = rec.type & 0xFF;
//        buffer[pos++] = (rec.rclass >> 8) & 0xFF;
//        buffer[pos++] = rec.rclass & 0xFF;
//        uint32_t ttl = rec.ttl;
//        buffer[pos++] = (ttl >> 24) & 0xFF;
//        buffer[pos++] = (ttl >> 16) & 0xFF;
//        buffer[pos++] = (ttl >> 8) & 0xFF;
//        buffer[pos++] = ttl & 0xFF;
//        int rdlen_pos = pos;
//        pos += 2; // skip rdlength for now
//
//        int rdlength = 0;
//        switch (rec.type) {
//            case 0x0001: { // A
//                unsigned char addr[4];
//                if (inet_pton(AF_INET, rec.rdata_str.c_str(), addr) == 1) {
//                    if (pos + 4 > max_len) return false;
//                    memcpy(buffer + pos, addr, 4);
//                    pos += 4;
//                    rdlength = 4;
//                } else return false;
//                break;
//            }
//            case 0x001C: { // AAAA
//                unsigned char addr6[16];
//                if (inet_pton(AF_INET6, rec.rdata_str.c_str(), addr6) == 1) {
//                    if (pos + 16 > max_len) return false;
//                    memcpy(buffer + pos, addr6, 16);
//                    pos += 16;
//                    rdlength = 16;
//                } else return false;
//                break;
//            }
//            case 0x0005:
//            case 0x0002:
//            case 0x000C: { // CNAME, NS, PTR
//                // Encode domain name (no compression)
//                std::string rname = rec.rdata_str;
//                if (!rname.empty() && rname.back() == '.') rname.pop_back();
//                size_t rs = 0, re;
//                while ((re = rname.find('.', rs)) != std::string::npos) {
//                    int llen = re - rs;
//                    if (pos + 1 + llen > max_len) return false;
//                    buffer[pos++] = (unsigned char) llen;
//                    memcpy(buffer + pos, rname.c_str() + rs, llen);
//                    pos += llen;
//                    rs = re + 1;
//                }
//                int llen = rname.length() - rs;
//                if (pos + 1 + llen > max_len) return false;
//                buffer[pos++] = (unsigned char) llen;
//                memcpy(buffer + pos, rname.c_str() + rs, llen);
//                pos += llen;
//                buffer[pos++] = 0;
//                rdlength = pos - (rdlen_pos + 2);
//                break;
//            }
//            case 0x000F: { // MX
//                // Format: preference (2 bytes) + exchange name
//                size_t space = rec.rdata_str.find(' ');
//                if (space == std::string::npos) return false;
//                int pref = std::stoi(rec.rdata_str.substr(0, space));
//                std::string mx = rec.rdata_str.substr(space + 1);
//                if (pos + 2 > max_len) return false;
//                buffer[pos++] = (pref >> 8) & 0xFF;
//                buffer[pos++] = pref & 0xFF;
//                // encode mx name
//                if (!mx.empty() && mx.back() == '.') mx.pop_back();
//                size_t ms = 0, me;
//                while ((me = mx.find('.', ms)) != std::string::npos) {
//                    int llen = me - ms;
//                    if (pos + 1 + llen > max_len) return false;
//                    buffer[pos++] = (unsigned char) llen;
//                    memcpy(buffer + pos, mx.c_str() + ms, llen);
//                    pos += llen;
//                    ms = me + 1;
//                }
//                int llen = mx.length() - ms;
//                if (pos + 1 + llen > max_len) return false;
//                buffer[pos++] = (unsigned char) llen;
//                memcpy(buffer + pos, mx.c_str() + ms, llen);
//                pos += llen;
//                buffer[pos++] = 0;
//                rdlength = pos - (rdlen_pos + 2);
//                break;
//            }
//            case 0x0010: { // TXT
//                // rdata_str may contain multiple strings separated by space; we'll treat as one string
//                if (pos + 1 + rec.rdata_str.length() > max_len) return false;
//                buffer[pos++] = (unsigned char) rec.rdata_str.length();
//                memcpy(buffer + pos, rec.rdata_str.c_str(), rec.rdata_str.length());
//                pos += rec.rdata_str.length();
//                rdlength = pos - (rdlen_pos + 2);
//                break;
//            }
//            default:
//                // Unsupported type, return false to skip record (or could encode as unknown)
//                return false;
//        }
//
//        // Write actual rdlength
//        buffer[rdlen_pos] = (rdlength >> 8) & 0xFF;
//        buffer[rdlen_pos + 1] = rdlength & 0xFF;
//        return true;
//    };
//
//    // Write answer records
//    for (const auto &rec: resp.answers) {
//        if (!write_rr(rec)) return -1; // if fails, abort
//    }
//    // Write authority records (optional)
//    for (const auto &rec: resp.authorities) {
//        if (!write_rr(rec)) return -1;
//    }
//    // Write additional records (optional)
//    for (const auto &rec: resp.additionals) {
//        if (!write_rr(rec)) return -1;
//    }
//
//    return pos;
//}

int build_dns_response(const DnsResponse &resp, unsigned char *buffer, int max_len) {
    if (!resp.valid || max_len < 12) return -1;

    memset(buffer, 0, max_len);
    int pos = 12; // DNS header size

    // ========== 1. Header ==========
    buffer[0] = (resp.header.id >> 8) & 0xFF;
    buffer[1] = resp.header.id & 0xFF;

    uint16_t flags = 0;
    if (resp.header.qr) flags |= 0x8000;
    flags |= (resp.header.opcode & 0x0F) << 11;
    if (resp.header.aa) flags |= 0x0400;
    if (resp.header.tc) flags |= 0x0200;
    if (resp.header.rd) flags |= 0x0100;
    if (resp.header.ra) flags |= 0x0080;
    flags |= (resp.header.rcode & 0x0F);
    buffer[2] = (flags >> 8) & 0xFF;
    buffer[3] = flags & 0xFF;

    // Counts will be filled later
    int qdcount_pos = 4;
    int ancount_pos = 6;
    int nscount_pos = 8;
    int arcount_pos = 10;

    // ========== 2. Question section ==========
    uint16_t qdcount = 0;
    for (const auto &q: resp.questions) {
        // Write domain name (simple encoding, no compression)
        std::string name = q.name;
        if (!name.empty() && name.back() == '.') name.pop_back();
        size_t start = 0, end;
        bool ok = true;
        while ((end = name.find('.', start)) != std::string::npos) {
            int label_len = end - start;
            if (pos + 1 + label_len > max_len) {
                ok = false;
                break;
            }
            buffer[pos++] = (unsigned char) label_len;
            memcpy(buffer + pos, name.c_str() + start, label_len);
            pos += label_len;
            start = end + 1;
        }
        if (!ok) break;
        int last_len = name.length() - start;
        if (pos + 1 + last_len + 4 > max_len) break;
        buffer[pos++] = (unsigned char) last_len;
        memcpy(buffer + pos, name.c_str() + start, last_len);
        pos += last_len;
        buffer[pos++] = 0; // terminating zero length label

        buffer[pos++] = (q.qtype >> 8) & 0xFF;
        buffer[pos++] = q.qtype & 0xFF;
        buffer[pos++] = 0; // qclass IN
        buffer[pos++] = 1;
        qdcount++;
    }
    buffer[qdcount_pos] = (qdcount >> 8) & 0xFF;
    buffer[qdcount_pos + 1] = qdcount & 0xFF;

    // ========== 3. Helper lambda to write a resource record ==========
    auto write_rr = [&](const DnsRecord &rec) -> bool {
        int start_pos = pos;
        // Write owner name
        std::string name = rec.name;
        if (!name.empty() && name.back() == '.') name.pop_back();
        size_t start = 0, end;
        while ((end = name.find('.', start)) != std::string::npos) {
            int label_len = end - start;
            if (pos + 1 + label_len > max_len) {
                pos = start_pos;
                return false;
            }
            buffer[pos++] = (unsigned char) label_len;
            memcpy(buffer + pos, name.c_str() + start, label_len);
            pos += label_len;
            start = end + 1;
        }
        int last_len = name.length() - start;
        if (pos + 1 + last_len + 10 > max_len) {
            pos = start_pos;
            return false;
        }
        buffer[pos++] = (unsigned char) last_len;
        memcpy(buffer + pos, name.c_str() + start, last_len);
        pos += last_len;
        buffer[pos++] = 0;

        // Type, class, TTL, RDLENGTH placeholder
        buffer[pos++] = (rec.type >> 8) & 0xFF;
        buffer[pos++] = rec.type & 0xFF;
        buffer[pos++] = (rec.rclass >> 8) & 0xFF;
        buffer[pos++] = rec.rclass & 0xFF;
        uint32_t ttl = rec.ttl;
        buffer[pos++] = (ttl >> 24) & 0xFF;
        buffer[pos++] = (ttl >> 16) & 0xFF;
        buffer[pos++] = (ttl >> 8) & 0xFF;
        buffer[pos++] = ttl & 0xFF;
        int rdlen_pos = pos;
        pos += 2; // skip rdlength

        int rdlength = 0;
        bool handled = false;

        switch (rec.type) {
            case 0x0001: { // A
                unsigned char addr[4];
                if (inet_pton(AF_INET, rec.rdata_str.c_str(), addr) == 1) {
                    if (pos + 4 <= max_len) {
                        memcpy(buffer + pos, addr, 4);
                        pos += 4;
                        rdlength = 4;
                        handled = true;
                    }
                }
                break;
            }
            case 0x001C: { // AAAA
                unsigned char addr6[16];
                if (inet_pton(AF_INET6, rec.rdata_str.c_str(), addr6) == 1) {
                    if (pos + 16 <= max_len) {
                        memcpy(buffer + pos, addr6, 16);
                        pos += 16;
                        rdlength = 16;
                        handled = true;
                    }
                }
                break;
            }
            case 0x0005:
            case 0x0002:
            case 0x000C: { // CNAME, NS, PTR
                std::string rname = rec.rdata_str;
                if (!rname.empty() && rname.back() == '.') rname.pop_back();
                size_t rs = 0, re;
                bool ok = true;
                int start_rr_pos = pos;
                while ((re = rname.find('.', rs)) != std::string::npos) {
                    int llen = re - rs;
                    if (pos + 1 + llen > max_len) {
                        ok = false;
                        break;
                    }
                    buffer[pos++] = (unsigned char) llen;
                    memcpy(buffer + pos, rname.c_str() + rs, llen);
                    pos += llen;
                    rs = re + 1;
                }
                if (!ok) break;
                int llen = rname.length() - rs;
                if (pos + 1 + llen > max_len) break;
                buffer[pos++] = (unsigned char) llen;
                memcpy(buffer + pos, rname.c_str() + rs, llen);
                pos += llen;
                buffer[pos++] = 0;
                rdlength = pos - start_rr_pos;
                handled = true;
                break;
            }
            case 0x000F: { // MX
                size_t space = rec.rdata_str.find(' ');
                if (space != std::string::npos) {
                    int pref = std::stoi(rec.rdata_str.substr(0, space));
                    std::string mx = rec.rdata_str.substr(space + 1);
                    if (!mx.empty() && mx.back() == '.') mx.pop_back();
                    if (pos + 2 <= max_len) {
                        buffer[pos++] = (pref >> 8) & 0xFF;
                        buffer[pos++] = pref & 0xFF;
                        int start_rr_pos = pos;
                        size_t ms = 0, me;
                        bool ok = true;
                        while ((me = mx.find('.', ms)) != std::string::npos) {
                            int llen = me - ms;
                            if (pos + 1 + llen > max_len) {
                                ok = false;
                                break;
                            }
                            buffer[pos++] = (unsigned char) llen;
                            memcpy(buffer + pos, mx.c_str() + ms, llen);
                            pos += llen;
                            ms = me + 1;
                        }
                        if (ok) {
                            int llen = mx.length() - ms;
                            if (pos + 1 + llen <= max_len) {
                                buffer[pos++] = (unsigned char) llen;
                                memcpy(buffer + pos, mx.c_str() + ms, llen);
                                pos += llen;
                                buffer[pos++] = 0;
                                rdlength = pos - start_rr_pos;
                                handled = true;
                            }
                        }
                    }
                }
                break;
            }
            case 0x0010: { // TXT (treated as one string)
                if (pos + 1 + rec.rdata_str.length() <= max_len) {
                    buffer[pos++] = (unsigned char) rec.rdata_str.length();
                    memcpy(buffer + pos, rec.rdata_str.c_str(), rec.rdata_str.length());
                    pos += rec.rdata_str.length();
                    rdlength = rec.rdata_str.length() + 1;
                    handled = true;
                }
                break;
            }
            default:
                break; // unsupported type, skip
        }

        if (!handled) {
            // rollback and skip this record
            pos = start_pos;
            return false;
        }

        // Fill rdlength
        buffer[rdlen_pos] = (rdlength >> 8) & 0xFF;
        buffer[rdlen_pos + 1] = rdlength & 0xFF;
        return true;
    };

    // ========== 4. Write answer records ==========
    uint16_t ancount = 0;
    for (const auto &rec: resp.answers) {
        if (write_rr(rec)) {
            ancount++;
        }
    }
    buffer[ancount_pos] = (ancount >> 8) & 0xFF;
    buffer[ancount_pos + 1] = ancount & 0xFF;

    // ========== 5. Write authority records ==========
    uint16_t nscount = 0;
    for (const auto &rec: resp.authorities) {
        if (write_rr(rec)) {
            nscount++;
        }
    }
    buffer[nscount_pos] = (nscount >> 8) & 0xFF;
    buffer[nscount_pos + 1] = nscount & 0xFF;

    // ========== 6. Write additional records ==========
    uint16_t arcount = 0;
    for (const auto &rec: resp.additionals) {
        if (write_rr(rec)) {
            arcount++;
        }
    }
    buffer[arcount_pos] = (arcount >> 8) & 0xFF;
    buffer[arcount_pos + 1] = arcount & 0xFF;

    return pos;
}
