#include <iostream>
#include <string>
#include <cstring>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#define DEFAULT_MGMT_PORT 953

int main(int argc, char *argv[]) {
    std::string server = "127.0.0.1";
    int port = DEFAULT_MGMT_PORT;
    std::string command;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else {
            if (!command.empty()) command += " ";
            command += argv[i];
        }
    }

    if (command.empty()) {
        std::cerr << "Usage: " << argv[0] << " [-p port] <command> [args...]\n";
        return 1;
    }

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error creating socket\n";
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server.c_str(), &addr.sin_addr);

    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        std::cerr << "Error connecting to management server at " << server << ":" << port << "\n";
        return 1;
    }

    // 发送命令
    send(sock, command.c_str(), command.length(), 0);

    // 接收响应
    char buf[4096];
    std::string response;
    int n;
    while ((n = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        response += buf;
    }

    std::cout << response;

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif

    return 0;
}
