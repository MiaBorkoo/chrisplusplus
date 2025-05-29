cmake_minimum_required(VERSION 3.19)
project(tofu LANGUAGES CXX)

# Create the TOFU library
add_library(tofu
    DeviceCertificate.h
    DeviceCertificate.cpp
    TrustStoreEntry.h
    TrustStoreEntry.cpp
    TOFUPromptManager.h
    TOFUPromptManager.cpp
)

# Link dependencies
target_link_libraries(tofu
    PUBLIC
        Qt6::Core
        OpenSSL::SSL
        OpenSSL::Crypto
)

# Include directories
target_include_directories(tofu
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
) 