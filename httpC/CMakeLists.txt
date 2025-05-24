cmake_minimum_required(VERSION 3.19)
project(http_layer LANGUAGES CXX)

# the http_layer library
add_library(http_layer
    HttpRequest.h
    HttpRequest.cpp
    HttpResponse.h
    HttpResponse.cpp
    HttpClient.h
    HttpClient.cpp
)

# include paths: your own headers + the sockets module
target_include_directories(http_layer
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}  # for Http*.h
)
target_link_libraries(http_layer
    PUBLIC sockets                       
)
