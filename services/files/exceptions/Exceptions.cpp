#include "Exceptions.h"

FileException::FileException(FileError type, const std::string& msg) 
    : error_type(type), message(msg) {
}

const char* FileException::what() const noexcept {
    return message.c_str();
}

FileError FileException::get_error_type() const {
    return error_type;
} 