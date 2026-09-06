cmake_minimum_required(VERSION 3.25)
project(PrivyDNS)

set(CMAKE_CXX_STANDARD 17)

if (MSVC)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /source-charset:utf-8 /execution-charset:utf-8")
endif ()

find_package(httplib CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

set(COMMON_SOURCES
        src/dns_packet.cpp
        src/dns_services.cpp
        src/proxy_handler.cpp)

add_executable(dns_client src/client.cpp ${COMMON_SOURCES})
target_link_libraries(dns_client PRIVATE httplib::httplib OpenSSL::SSL  OpenSSL::Crypto)

add_executable(dns_server src/server.cpp ${COMMON_SOURCES} src/dns_cache.cpp src/dns_server.cpp)
target_link_libraries(dns_server PRIVATE httplib::httplib OpenSSL::SSL  OpenSSL::Crypto)

add_executable(dns_server_ctl src/server_ctl.cpp)

if(WIN32)
    target_link_libraries(dns_client PRIVATE iphlpapi ws2_32)
    target_sources(dns_client PRIVATE res/win/app.rc)

    target_link_libraries(dns_server PRIVATE iphlpapi ws2_32)
    target_sources(dns_server PRIVATE res/win/app.rc)

    target_link_libraries(dns_server_ctl PRIVATE iphlpapi ws2_32)
    target_sources(dns_server_ctl PRIVATE res/win/app.rc)
endif()

