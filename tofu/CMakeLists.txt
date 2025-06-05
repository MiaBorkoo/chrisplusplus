cmake_minimum_required(VERSION 3.19)
project(tofu LANGUAGES CXX)

# Find qrencode package
find_package(PkgConfig REQUIRED)
pkg_check_modules(QRENCODE REQUIRED libqrencode)

# Create the TOFU library
add_library(tofu
    DeviceCertificate.h
    DeviceCertificate.cpp
    TrustStoreEntry.h
    TrustStoreEntry.cpp
    TOFUPromptManager.h
    TOFUPromptManager.cpp
    QRVerification.h
    QRVerification.cpp
)
set_target_properties(tofu PROPERTIES LINKER_LANGUAGE CXX)

# Link dependencies
target_link_libraries(tofu
    PUBLIC
        Qt6::Core
        Qt6::Concurrent
        OpenSSL::SSL
        OpenSSL::Crypto
        ${QRENCODE_LIBRARIES}
)

# Include directories
target_include_directories(tofu
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${QRENCODE_INCLUDE_DIRS}
)

# Add library directories for qrencode on macOS
if(APPLE)
    target_link_directories(tofu PUBLIC /opt/homebrew/lib)
endif() 