cmake_minimum_required(VERSION 3.16)
project(LoginApp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS 
    Core
    Widgets
    Network
    REQUIRED
)

#Temporarily comment out sockets
#add_subdirectory(sockets)

# Create resources file for the css file and logo
set(RESOURCE_FILES
    resources.qrc
)


add_executable(LoginApp
    MACOSX_BUNDLE
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
    ${RESOURCE_FILES}
)

target_link_libraries(LoginApp
    PRIVATE
        Qt6::Core
        Qt6::Widgets
        Qt6::Network
        #sockets
)

include(GNUInstallDirs)

# Temporarily commented out SSL test
#add_executable(testSSLforNow
#    testSSLforNow.cpp
#)
#target_link_libraries(testSSLforNow
#    PRIVATE 
#        sockets
#        Qt6::Core
#        Qt6::Network
#)

install(TARGETS LoginApp
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

qt_generate_deploy_app_script(
    TARGET LoginApp
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)

install(SCRIPT ${deploy_script})

if(MSVC)
    target_compile_options(LoginApp PRIVATE /W4)
else()
    target_compile_options(LoginApp PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(LoginApp PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.yourcompany.loginapp"
    MACOSX_BUNDLE_BUNDLE_NAME "LoginApp"
    MACOSX_BUNDLE_BUNDLE_VERSION "1.0"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0"
)