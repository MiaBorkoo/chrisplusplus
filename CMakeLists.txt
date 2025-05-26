cmake_minimum_required(VERSION 3.19)
project(LoginForm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt configuration
set(CMAKE_AUTOMOC ON)#handles qts meta object compiler
set(CMAKE_AUTORCC ON) #handles QT resources files
set(CMAKE_AUTOUIC ON) #handles QT UI files


# Find required packages
find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets Network)
find_package(OpenSSL REQUIRED)

qt_standard_project_setup()

# add_subdirectory(sockets)

# Create resources file for the css file and logo
set(RESOURCE_FILES
    resources.qrc
)

# Main executable
qt_add_executable(LoginForm
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
    ${RESOURCE_FILES}
)

# Link libraries
target_link_libraries(LoginForm
    PRIVATE
        Qt6::Core
        Qt6::Widgets
        Qt6::Network
        OpenSSL::SSL
        #sockets
)

# Include directories
target_include_directories(LoginForm
    PRIVATE
        ${CMAKE_SOURCE_DIR}/views
        ${CMAKE_SOURCE_DIR}/controllers
        ${CMAKE_SOURCE_DIR}/sockets
)

# test
# add_executable(testSSLforNow
#    testSSLforNow.cpp
# )
# target_link_libraries(testSSLforNow
#    PRIVATE 
#        sockets
#        Qt6::Core
#        Qt6::Network
# )

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
