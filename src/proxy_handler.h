#ifndef DNS_QUERY_PROXY_HANDLER_H
#define DNS_QUERY_PROXY_HANDLER_H

#include <string>

#ifdef _WIN32
#include <winsock2.h>
#endif

#ifdef _WIN32

int connect_via_socks5(SOCKET sock, const std::string &p_host, int p_port, const std::string &t_host, int t_port);

int connect_via_http_proxy(SOCKET sock, const std::string &p_host, int p_port, const std::string &t_host, int t_port);

#else

int connect_via_socks5(int sock, const std::string& p_host, int p_port, const std::string& t_host, int t_port);

int connect_via_http_proxy(int sock, const std::string& p_host, int p_port, const std::string& t_host, int t_port);

#endif

#endif //DNS_QUERY_PROXY_HANDLER_H
