cmake_minimum_required(VERSION 3.19)
project(LoginForm LANGUAGES CXX)

# Provide a default OpenSSL path (optional, can be overridden)
# Use a common path or leave empty to let CMake search standard locations
set(OPENSSL_ROOT_DIR "" CACHE PATH "Path to OpenSSL root directory")

# Find required packages
find_package(Qt6 6.9 REQUIRED COMPONENTS Core Widgets Network) # Updated to 6.9 to match your Qt path
find_package(OpenSSL REQUIRED)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt setup
qt_standard_project_setup()

# Add subdirectories (only for sockets, which defines a library)
add_subdirectory(sockets)

# Define the main executable with all source files
qt_add_executable(LoginForm
    WIN32 MACOSX_BUNDLE
    main.cpp
    models/LoginModel.cpp
    database/Database.cpp
    database/UserDatabase.cpp
    database/AuthClient.cpp
)

# Link libraries
target_link_libraries(LoginForm
    PRIVATE
        Qt6::Core
        Qt6::Widgets
        Qt6::Network
        OpenSSL::SSL
        sockets
)

# Include directories for headers
target_include_directories(LoginForm
    PRIVATE
        ${CMAKE_SOURCE_DIR}/sockets
        ${CMAKE_SOURCE_DIR}/models
        ${CMAKE_SOURCE_DIR}/database
)

# Install targets
install(TARGETS LoginForm
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Generate deployment script
qt_generate_deploy_app_script(
    TARGET LoginForm
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})

# Test executable
add_executable(testSSLforNow
    testSSLforNow.cpp
)
target_link_libraries(testSSLforNow
    PRIVATE
        sockets
        Qt6::Core
        OpenSSL::SSL
)
target_include_directories(testSSLforNow
    PRIVATE
        ${CMAKE_SOURCE_DIR}/sockets
)