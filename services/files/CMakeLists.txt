# File Management and Sharing System
cmake_minimum_required(VERSION 3.16)

# Find required packages for file management
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)
find_package(nlohmann_json REQUIRED)

# File Management System Sources
set(FILE_MANAGEMENT_SOURCES
    exceptions/Exceptions.cpp
    network/HTTPClient.cpp
    encryption/FileEncryptionEngine.cpp
    FileManager.cpp
)

# Create File Management library
add_library(FileManagement ${FILE_MANAGEMENT_SOURCES})

# Include directories for the library
target_include_directories(FileManagement 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/models
        ${CMAKE_CURRENT_SOURCE_DIR}/network
        ${CMAKE_CURRENT_SOURCE_DIR}/encryption
        ${CMAKE_CURRENT_SOURCE_DIR}/interfaces
        ${CMAKE_CURRENT_SOURCE_DIR}/exceptions
)

# Link required libraries
target_link_libraries(FileManagement
    PUBLIC
        ${LIBSODIUM_LIBRARIES}
        nlohmann_json::nlohmann_json
        curl
)

# Compiler options
target_compile_options(FileManagement PRIVATE ${LIBSODIUM_CFLAGS_OTHER})
target_include_directories(FileManagement PRIVATE ${LIBSODIUM_INCLUDE_DIRS}) 