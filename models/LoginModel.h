#ifndef LOGIN_MODEL_H
#define LOGIN_MODEL_H

#include <string>
#include <vector>

class UserData;
class FileData;

class LoginModel {
public:
    LoginModel();

    // User functions
    bool login(const std::string& username, const std::string& key);
    bool signUp(const std::string& username, const std::string& key);
    bool changePassword(const std::string& username, const std::string& oldKey, const std::string& newKey);
    bool validateCredentials();
    UserData getUserData(const std::string& username);

    // File functions
    std::vector<FileData> listOwnedFiles(const std::string& username);
    std::vector<FileData> listSharedFiles(const std::string& username);
    bool shareFile(const std::string& filename, const std::string& recipientUsername);
    bool revokeFile(const std::string& filename, const std::string& recipientUsername);
    bool deleteFile(const std::string& filename);
    bool uploadFile(const std::string& filename, const std::string& recipientUsername);
};

#endif // LOGIN_MODEL_H
