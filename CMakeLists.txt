cmake_minimum_required(VERSION 3.19)
project(LoginForm LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets Network)
find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

qt_standard_project_setup()

add_subdirectory(sockets) #for adding a sockets library in /sockets, BUT CHECK IF THIS IS CORRECT (its correct, Well done Mia!)

qt_add_executable(LoginForm
    WIN32 MACOSX_BUNDLE
    main.cpp
    database/auth/AuthDatabase.cpp
    models/LoginModel.cpp
)


target_link_libraries(LoginForm
    PRIVATE
        Qt6::Core
        Qt6::Widgets
        Qt6::Network
        OpenSSL::SSL
        sockets
)
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

# Test
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