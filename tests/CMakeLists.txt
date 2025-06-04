cmake_minimum_required(VERSION 3.16)
project(EngineTests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)
find_package(nlohmann_json REQUIRED)

# Find zlib
pkg_check_modules(ZLIB REQUIRED zlib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${GTEST_INCLUDE_DIRS})

# Source files for the engines being tested
set(ENGINE_SOURCES
    ../services/files/compression/CompressionEngine.cpp
    ../services/files/serialization/SerializationEngine.cpp
    ../services/files/encryption/FileEncryptionEngine.cpp
    ../services/files/exceptions/Exceptions.cpp
)

# Test executable
add_executable(engine_tests 
    test_engines.cpp
    ${ENGINE_SOURCES}
)

# Link libraries
target_link_libraries(engine_tests
    ${GTEST_LIBRARIES}
    ${GTEST_MAIN_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
    nlohmann_json::nlohmann_json
    pthread
)

# Compiler flags
target_compile_options(engine_tests PRIVATE ${ZLIB_CFLAGS_OTHER})

# Enable testing
enable_testing()
add_test(NAME EngineTests COMMAND engine_tests) 