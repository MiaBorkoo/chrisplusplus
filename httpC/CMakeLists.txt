cmake_minimum_required(VERSION 3.19)
project(http_layer LANGUAGES CXX)

# 1. Declare the http_layer library
add_library(http_layer
    HttpRequest.h
    HttpResponse.h
    HttpClient.h
    HttpClient.cpp
)

# 2. Include paths: your own headers + the sockets module
target_include_directories(http_layer
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}  # for Http*.h
)
target_link_libraries(http_layer
    PUBLIC sockets                       # link your TLS code
)
