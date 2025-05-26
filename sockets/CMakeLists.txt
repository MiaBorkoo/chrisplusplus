cmake_minimum_required(VERSION 3.19)
project(sockets LANGUAGES CXX)


find_package(OpenSSL REQUIRED)


# this is the defining the sockets library (our ssl library lets call it that)
add_library(sockets
    SSLContext.cpp
    SSLContext.h
    SSLConnection.cpp
    SSLConnection.h
)


target_include_directories(sockets
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}  # for sockets/*.h files
        ${OPENSSL_INCLUDE_DIR}       # for <openssl/*.h>
)

# link OpenSSL in
target_link_libraries(sockets
    PUBLIC
        Qt6::Core
        OpenSSL::SSL
        OpenSSL::Crypto
)
