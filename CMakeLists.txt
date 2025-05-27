cmake_minimum_required(VERSION 3.19)
project(ChrisPlusPlus LANGUAGES CXX)

# Disable warnings as errors
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error")

# Remove EXACT to allow newer compatible versions
find_package(Qt6 6.9.0 REQUIRED COMPONENTS Core Widgets)

qt_standard_project_setup()

# Add subdirectories for libraries
add_subdirectory(sockets)
add_subdirectory(httpC)
add_subdirectory(fileIO)

# Main application
qt_add_executable(ChrisPlusPlus
    WIN32 MACOSX_BUNDLE
    # Main application entry point
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
)

target_link_libraries(ChrisPlusPlus
    PRIVATE
        # Qt libraries
        Qt6::Core
        Qt6::Widgets
        file_transfer
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
target_link_libraries(testSSLforNow PRIVATE sockets http_layer)



add_executable(testComplete
    tests/testComplete.cpp
)
target_link_libraries(testComplete PRIVATE sockets http_layer)



# Add simple upload test for debugging
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

# Complete network system demo
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
