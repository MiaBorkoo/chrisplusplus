cmake_minimum_required(VERSION 3.19)
project(LoginForm LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets)

qt_standard_project_setup()

add_subdirectory(sockets) #for adding a sockets library in /sockets, BUT CHECK IF THIS IS CORRECT (its correct, Well done Mia!)
add_subdirectory(models)
add_subdirectory(encryption)

qt_add_executable(LoginForm
    WIN32 MACOSX_BUNDLE
    models/LoginModel.cpp
)


target_link_libraries(LoginForm
    PRIVATE
        Qt::Core
        Qt::Widgets
        sockets
        encryption
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