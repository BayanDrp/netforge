cmake_minimum_required(VERSION 3.14)

project(netforge VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(netforge STATIC
    src/buffer/buffer.cpp
    src/layers/ethernet.cpp
    src/layers/ipv4.cpp
    src/layers/udp.cpp
    src/layers/tcp.cpp
    src/layers/dns.cpp
    src/layers/http.cpp
    src/io/raw_socket.cpp
)

target_include_directories(netforge PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(netforge PRIVATE -Wall -Wextra -Werror)

enable_testing()

function(netforge_add_executable target source)
    file(SIZE "${CMAKE_CURRENT_SOURCE_DIR}/${source}" _size)
    if(_size GREATER 0)
        add_executable(${target} ${source})
        target_link_libraries(${target} PRIVATE netforge)
        target_compile_options(${target} PRIVATE -Wall -Wextra)
    endif()
endfunction()

netforge_add_executable(example_craft examples/cpp/craft.cpp)
netforge_add_executable(example_dns_query examples/cpp/dns_query.cpp)
netforge_add_executable(example_sniff examples/cpp/sniff.cpp)
netforge_add_executable(example_tcp_handshake examples/cpp/tcp_handshake.cpp)

netforge_add_executable(test_checksum tests/cpp/test_checksum.cpp)
netforge_add_executable(test_dns tests/cpp/test_dns.cpp)
netforge_add_executable(test_ethernet tests/cpp/test_ethernet.cpp)
netforge_add_executable(test_ipv4 tests/cpp/test_ipv4.cpp)
netforge_add_executable(test_tcp tests/cpp/test_tcp.cpp)

foreach(_test test_checksum test_dns test_ethernet test_ipv4 test_tcp)
    if(TARGET ${_test})
        add_test(NAME ${_test} COMMAND ${_test})
    endif()
endforeach()