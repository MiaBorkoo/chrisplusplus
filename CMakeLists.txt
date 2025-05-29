cmake_minimum_required(VERSION 3.19)
project(ChrisPlusPlus LANGUAGES CXX)

# Disable warnings as errors
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error")

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
        "/home/ruan/Qt/6.9.0/gcc_64"
        "/opt/Qt/6.7.0/gcc_64"
        "/usr/lib/x86_64-linux-gnu/cmake/Qt6"
        ${CMAKE_PREFIX_PATH}
    )
    message(STATUS "🐧 Linux: Using standard Qt paths")
endif()

# Find required packages
find_package(Qt6 6.5.0 REQUIRED COMPONENTS Core Widgets Network Test)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

qt_standard_project_setup()

# ============================================================================
# Add subdirectories for ALL libraries
# ============================================================================
add_subdirectory(sockets)    # SSL/TLS layer (shared by both systems)
add_subdirectory(httpC)      # HTTP protocol layer (YOUR addition)
add_subdirectory(fileIO)     # File transfer layer (YOUR addition)


# Main application with authentication
qt_add_executable(ChrisPlusPlus
    WIN32 MACOSX_BUNDLE
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
)


target_link_libraries(LoginForm
    PRIVATE
        Qt::Core
        Qt::Widgets
        sockets
)
include(GNUInstallDirs)

add_executable(testSSLforNow #testing my ssl library here temp 
    testSSLforNow.cpp
)
target_link_libraries(testSSLforNow
    PRIVATE sockets
)

install(TARGETS LoginForm
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

qt_generate_deploy_app_script(
    TARGET LoginForm
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})