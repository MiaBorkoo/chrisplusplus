# crypto/CMakeLists.txt

# =============================================
# Argon2 - Cross Platform Support
# =============================================
if(APPLE)
    set(ARGON2_INCLUDE_DIR "/opt/homebrew/opt/argon2/include")
    set(ARGON2_LIBRARY "/opt/homebrew/opt/argon2/lib/libargon2.dylib")
elseif(WIN32)
    # customise this path depending on where Windows users install argon2
    set(ARGON2_INCLUDE_DIR "C:/libs/argon2/include")
    set(ARGON2_LIBRARY "C:/libs/argon2/lib/argon2.lib")
elseif(UNIX)
    #example for Linux 
    set(ARGON2_INCLUDE_DIR "/usr/include")
    set(ARGON2_LIBRARY "/usr/lib/x86_64-linux-gnu/libargon2.so")
endif()

# Import the argon2 library
add_library(argon2 SHARED IMPORTED)
set_target_properties(argon2 PROPERTIES
    IMPORTED_LOCATION ${ARGON2_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${ARGON2_INCLUDE_DIR}
)

add_library(crypto-lib
    AuthHash.cpp
    KeyDerivation.cpp
    MEKGenerator.cpp
    WrappedMEK.cpp
)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

target_include_directories(crypto-lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(crypto-lib PUBLIC argon2 OpenSSL::Crypto)