# File Management and Sharing System
cmake_minimum_required(VERSION 3.15)
project(FileManagementSystem)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set Qt path
set(CMAKE_PREFIX_PATH "/home/ruan/Qt/6.9.0/gcc_64")

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(nlohmann_json REQUIRED)
pkg_check_modules(ZLIB REQUIRED zlib)
pkg_check_modules(LIBZIP REQUIRED libzip)
find_package(Qt6 REQUIRED COMPONENTS Core)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../)  # For sockets and httpC

# Exceptions library
add_library(ExceptionsLib
    exceptions/Exceptions.cpp
    exceptions/Exceptions.h
)

# SSL Context library
add_library(SSLContextLib
    ../../sockets/SSLContext.cpp
    ../../sockets/SSLContext.h
    ../../sockets/SSLConnection.cpp
    ../../sockets/SSLConnection.h
)
target_link_libraries(SSLContextLib OpenSSL::SSL OpenSSL::Crypto)

# HTTP Client Core (Qt-based)
add_library(HttpClientCore
    ../../httpC/HttpClient.cpp
    ../../httpC/HttpClient.h
    ../../httpC/HttpRequest.cpp
    ../../httpC/HttpRequest.h
    ../../httpC/HttpResponse.cpp
    ../../httpC/HttpResponse.h
)
target_link_libraries(HttpClientCore 
    SSLContextLib 
    Qt6::Core
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# Compression Engine
add_library(CompressionEngine
    compression/CompressionEngine.cpp
    compression/CompressionEngine.h
)
target_link_libraries(CompressionEngine ExceptionsLib ${ZLIB_LIBRARIES} ${LIBZIP_LIBRARIES})

# Data Converter (handles API format conversion)
add_library(DataConverter
    network/DataConverter.cpp
    network/DataConverter.h
)
target_link_libraries(DataConverter 
    ExceptionsLib
    OpenSSL::SSL 
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# File Service Client (handles REST API communication)
add_library(FileServiceClientLib
    network/FileServiceClient.cpp
    network/FileServiceClient.h
    network/AuthServiceClient.cpp
    network/AuthServiceClient.h
    network/FileOperationsClient.cpp
    network/FileOperationsClient.h
    network/SharingServiceClient.cpp
    network/SharingServiceClient.h
    network/AuditServiceClient.cpp
    network/AuditServiceClient.h
)
target_link_libraries(FileServiceClientLib
    DataConverter
    ExceptionsLib
    HttpClientCore
    SSLContextLib
    OpenSSL::SSL 
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# File Encryption Engine
add_library(FileEncryptionEngine
    encryption/FileEncryptionEngine.cpp
    encryption/FileEncryptionEngine.h
    models/DataModels.h
)
target_link_libraries(FileEncryptionEngine 
    ExceptionsLib
    CompressionEngine
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# File Manager (high-level interface)
add_library(FileManager
    FileManager.cpp
    FileManager.h
)
target_link_libraries(FileManager 
    FileEncryptionEngine
    FileServiceClientLib
    DataConverter
    ExceptionsLib
)

# Example executable
add_executable(FileManagementExample
    examples/FileManagementExample.cpp
)
target_link_libraries(FileManagementExample 
    FileManager
    FileEncryptionEngine
    FileServiceClientLib
    DataConverter
    CompressionEngine
    HttpClientCore
    SSLContextLib
    ExceptionsLib
    Qt6::Core
    OpenSSL::SSL 
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ${ZLIB_LIBRARIES} 
    ${LIBZIP_LIBRARIES}
)
