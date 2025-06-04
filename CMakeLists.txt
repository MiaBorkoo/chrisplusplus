cmake_minimum_required(VERSION 3.19)
project(ChrisPlusPlus LANGUAGES CXX)

# Disable warnings as errors
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error")

set(CMAKE_AUTOMOC ON) #handles qts meta object compiler
set(CMAKE_AUTORCC ON) #handles QT resources files
set(CMAKE_AUTOUIC ON) #handles QT UI files

if(APPLE)
    # macOS: Use Homebrew Qt (team-friendly!)
    execute_process(
        COMMAND brew --prefix qt6
        OUTPUT_VARIABLE QT_HOMEBREW_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    
    if(QT_HOMEBREW_PATH)
        message(STATUS "🍺 Using Homebrew Qt6: ${QT_HOMEBREW_PATH}")
        set(CMAKE_PREFIX_PATH "${QT_HOMEBREW_PATH}")
        set(Qt6_DIR "${QT_HOMEBREW_PATH}/lib/cmake/Qt6")
    else()
        message(STATUS "📦 Homebrew Qt6 not found, using system Qt")
    endif()
    
elseif(WIN32)
    # Windows: Common Qt installation paths
    set(CMAKE_PREFIX_PATH 
        "C:/Qt/6.7.0/msvc2019_64"
        "C:/Qt/6.8.0/msvc2022_64" 
        ${CMAKE_PREFIX_PATH}
    )

    message(STATUS "🪟 Windows: Searching common Qt paths")
    
else()
    # Linux: Standard paths
    set(CMAKE_PREFIX_PATH 
        "/opt/Qt/6.7.0/gcc_64"
        "/usr/lib/x86_64-linux-gnu/cmake/Qt6"
        ${CMAKE_PREFIX_PATH}
    )
    message(STATUS "🐧 Linux: Using standard Qt paths")
endif()

# Find required packages
find_package(Qt6 6.5.0 REQUIRED COMPONENTS Core Widgets Network Test Concurrent)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(RESOURCE_FILES
    resources.qrc
)

qt_standard_project_setup()

# ============================================================================
# Add subdirectories for ALL libraries
# ============================================================================
add_subdirectory(sockets)    # SSL/TLS layer (shared by both systems)
add_subdirectory(httpC)      # HTTP protocol layer
add_subdirectory(fileIO)     # File transfer layer 
add_subdirectory(crypto)     # Crypto library 
add_subdirectory(tofu)       # TOFU library

# Main application with authentication
qt_add_executable(ChrisPlusPlus
    WIN32 MACOSX_BUNDLE
    main.cpp
    mainwindow.cpp
    mainwindow.h
    views/LoginView.cpp
    views/LoginView.h
    views/SignUpView.cpp
    views/SignUpView.h
    controllers/LoginController.cpp
    controllers/LoginController.h
    controllers/SignUpController.cpp
    controllers/SignUpController.h
    views/HeaderWidget.cpp
    views/HeaderWidget.h
    views/SideNavWidget.cpp
    views/SideNavWidget.h
    views/FilesDashView.cpp
    views/FilesDashView.h
    controllers/FileDashController.cpp
    controllers/FileDashController.h
    views/SharedDashView.cpp
    views/SharedDashView.h
    controllers/SideNavController.cpp
    controllers/SideNavController.h
    controllers/SharedDashController.cpp
    controllers/SharedDashController.h
    views/AccessDialog.cpp
    views/AccessDialog.h
    controllers/AccessController.cpp
    controllers/AccessController.h
    models/SideNavTabs.h
    ${RESOURCE_FILES}
    # ✅ ADD: Authentication system
    models/LoginModel.cpp
    network/Client.cpp
    services/auth/AuthService.cpp
    services/ApiService.cpp
    services/auth/otp/TOTP.cpp
    services/auth/ValidationService.cpp
)

target_link_libraries(ChrisPlusPlus
    PRIVATE
        # Qt libraries
        Qt6::Core
        Qt6::Widgets
        Qt6::Network
        file_transfer
        http_layer
        sockets
        tofu           
        OpenSSL::SSL
        OpenSSL::Crypto
        crypto-lib
)

# Include directories (consolidated)
target_include_directories(ChrisPlusPlus
    PRIVATE
        ${CMAKE_SOURCE_DIR}/models
        ${CMAKE_SOURCE_DIR}/views
        ${CMAKE_SOURCE_DIR}/controllers
        ${CMAKE_SOURCE_DIR}/services
        ${CMAKE_SOURCE_DIR}/services/auth
        ${CMAKE_SOURCE_DIR}/network
        ${CMAKE_SOURCE_DIR}/sockets
        ${CMAKE_SOURCE_DIR}/httpC
        ${CMAKE_SOURCE_DIR}/fileIO
        ${CMAKE_SOURCE_DIR}/tofu   
)

# ============================================================================
# TEST EXECUTABLES
# ============================================================================

# Original test from dev branch
add_executable(testSSLforNow
    tests/testSSLforNow.cpp
)
target_link_libraries(testSSLforNow PRIVATE sockets http_layer)

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

add_executable(testKeyDerivation
    tests/testKeyDerivation.cpp
    crypto/KeyDerivation.cpp
)
target_link_libraries(testKeyDerivation PRIVATE crypto-lib)
target_include_directories(testKeyDerivation PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto
)

add_executable(testMEKGenerator
    tests/testMEKGenerator.cpp
    crypto/MEKGenerator.cpp
)
target_link_libraries(testMEKGenerator PRIVATE OpenSSL::Crypto)
target_include_directories(testMEKGenerator PRIVATE ${CMAKE_SOURCE_DIR}/crypto)

add_executable(testWrappedMEK
    tests/testWrappedMEK.cpp
    crypto/WrappedMEK.cpp
)
target_link_libraries(testWrappedMEK PRIVATE OpenSSL::Crypto)
target_include_directories(testWrappedMEK PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto
)

add_executable(testAuthHash
    tests/testAuthHash.cpp
    crypto/AuthHash.cpp
)
target_link_libraries(testAuthHash PRIVATE crypto-lib)
target_include_directories(testAuthHash PRIVATE ${CMAKE_SOURCE_DIR}/crypto)

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