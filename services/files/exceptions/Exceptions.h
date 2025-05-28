#pragma once

#include <exception>
#include <string>

enum class FileError {
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    INVALID_DEK,
    INTEGRITY_VERIFICATION_FAILED,
    UNAUTHORIZED_ACCESS,
    FILE_NOT_FOUND,
    RECIPIENT_NOT_TRUSTED,
    SHARE_CREATION_FAILED,
    INVALID_SESSION,
    SERVER_COMMUNICATION_ERROR
};

class FileException : public std::exception {
private:
    FileError error_type;
    std::string message;

public:
    FileException(FileError type, const std::string& msg);
    const char* what() const noexcept override;
    FileError get_error_type() const;
}; 