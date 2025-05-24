# FileIO library for streaming file transfers
add_library(file_transfer
    fileTransfer.h
    fileTransfer.cpp
)

target_link_libraries(file_transfer
    PUBLIC
        Qt::Core
        http_layer  
)

target_include_directories(file_transfer
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
) 