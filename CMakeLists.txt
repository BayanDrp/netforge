cmake_minimum_required(VERSION 3.14)

project(netforge VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_library(netforge STATIC
    src/buffer/buffer.cpp
    src/layers/ethernet.cpp
    src/layers/ipv4.cpp
    src/layers/udp.cpp
    src/layers/tcp.cpp
    src/layers/dns.cpp
    src/layers/http.cpp
    src/layers/icmp.cpp
    src/layers/ipv6.cpp
    src/io/raw_socket.cpp
    src/io/sniffer.cpp
    src/packet/mac.cpp
    src/parser/checksum.cpp
    src/parser/dissect.cpp
)

target_include_directories(netforge PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(netforge PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(netforge PRIVATE ${PCAP_LIBRARIES})
target_compile_options(netforge PRIVATE -Wall -Wextra -Werror)
set_target_properties(netforge PROPERTIES POSITION_INDEPENDENT_CODE ON)

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
netforge_add_executable(bench_parse benchmarks/bench_parse.cpp)

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

# Optional Python bindings (pybind11). Only built if pybind11 is installed.
find_package(Python COMPONENTS Interpreter Development QUIET)
find_package(pybind11 CONFIG QUIET)
if(Python_FOUND AND pybind11_FOUND)
    pybind11_add_module(netforge_bindings bindings/module.cpp)
    set_target_properties(netforge_bindings PROPERTIES
        OUTPUT_NAME _netforge
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/python/netforge
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/python/netforge)
    target_link_libraries(netforge_bindings PRIVATE netforge ${PCAP_LIBRARIES})
    target_include_directories(netforge_bindings PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_options(netforge_bindings PRIVATE -Wall -Wextra)
    message(STATUS "Python bindings enabled (pybind11 ${PYBIND11_VERSION})")
else()
    message(STATUS "Python bindings disabled (pybind11 or Python dev not found)")
endif()
