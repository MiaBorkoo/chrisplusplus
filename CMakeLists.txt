cmake_minimum_required(VERSION 3.19)
project(ChrisPlusPlus LANGUAGES CXX)

# Disable warnings as errors
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error")

# Find required packages
find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets Network)
find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

qt_standard_project_setup()

# ============================================================================
# Add subdirectories for ALL libraries
# ============================================================================
add_subdirectory(sockets)    # SSL/TLS layer (shared by both systems)
add_subdirectory(httpC)      # HTTP protocol layer (YOUR addition)
add_subdirectory(fileIO)     # File transfer layer (YOUR addition)

# ============================================================================
# MAIN APPLICATION: LoginForm + Secure File Transfer Combined
# ============================================================================
qt_add_executable(ChrisPlusPlus
    WIN32 MACOSX_BUNDLE
    # Main application entry point
    main.cpp
    
    # Authentication system (from dev branch - LoginForm)
    models/LoginModel.cpp
    network/Client.cpp
    services/auth/AuthService.cpp
    services/files/FileService.cpp
)

target_link_libraries(ChrisPlusPlus
    PRIVATE
        # Qt libraries
        Qt6::Core
        Qt6::Widgets
        Qt6::Network
        
        # OpenSSL libraries
        OpenSSL::SSL
        OpenSSL::Crypto
        
        # All libraries (dev branch + YOUR additions)
        sockets         # SSL/TLS (shared by both systems)
        http_layer      # YOUR HTTP protocol system
        file_transfer   # YOUR file transfer system
)

# Include directories (from dev branch + YOUR additions)
target_include_directories(ChrisPlusPlus
    PRIVATE
        ${CMAKE_SOURCE_DIR}/sockets
        ${CMAKE_SOURCE_DIR}/models
        ${CMAKE_SOURCE_DIR}/services
        ${CMAKE_SOURCE_DIR}/services/auth
        ${CMAKE_SOURCE_DIR}/services/files
        ${CMAKE_SOURCE_DIR}/network
        ${CMAKE_SOURCE_DIR}/httpC
        ${CMAKE_SOURCE_DIR}/fileIO
)

# ============================================================================
# TEST EXECUTABLES
# ============================================================================

# Original test from dev branch
add_executable(testSSLforNow
    tests/testSSLforNow.cpp
)
target_link_libraries(testSSLforNow
    PRIVATE
        sockets
        Qt6::Core
        OpenSSL::SSL
        OpenSSL::Crypto
)
target_include_directories(testSSLforNow
    PRIVATE
        ${CMAKE_SOURCE_DIR}/sockets
)

# YOUR secure file transfer tests
add_executable(testNetworkSystemComplete
    tests/testNetworkSystemComplete.cpp
)
target_link_libraries(testNetworkSystemComplete PRIVATE 
    Qt6::Core 
    Qt6::Widgets 
    file_transfer 
    http_layer 
    sockets
)

add_executable(testFileUploadSimple
    tests/testFileUploadSimple.cpp
)
target_link_libraries(testFileUploadSimple PRIVATE 
    Qt6::Core 
    Qt6::Widgets 
    file_transfer 
    http_layer 
    sockets
)


# ============================================================================
# INSTALLATION (updated for ChrisPlusPlus)
# ============================================================================
include(GNUInstallDirs)

install(TARGETS ChrisPlusPlus
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Generate deployment script
qt_generate_deploy_app_script(
    TARGET ChrisPlusPlus
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})
