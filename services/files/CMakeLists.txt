# File Management and Sharing System
cmake_minimum_required(VERSION 3.15)
project(FileManagementSystem)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZLIB REQUIRED zlib)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Compression Engine
add_library(CompressionEngine
    compression/CompressionEngine.cpp
    compression/CompressionEngine.h
)
target_link_libraries(CompressionEngine ${ZLIB_LIBRARIES})

# Serialization Engine  
add_library(SerializationEngine
    serialization/SerializationEngine.cpp
    serialization/SerializationEngine.h
)

# File Encryption Engine
add_library(FileEncryptionEngine
    encryption/FileEncryptionEngine.cpp
    encryption/FileEncryptionEngine.h
    models/DataModels.h
    exceptions/Exceptions.h
)
target_link_libraries(FileEncryptionEngine 
    OpenSSL::SSL 
    OpenSSL::Crypto
    CompressionEngine
    SerializationEngine
)

# Main file management library
add_library(FileManagement
    # Add other source files here as they're created
)
target_link_libraries(FileManagement FileEncryptionEngine)
