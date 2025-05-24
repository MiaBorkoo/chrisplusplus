#include "LoginModel.h"

LoginModel::LoginModel(UserDatabase* userDb = nullptr, QObject* parent = nullptr)
    : QObject(parent), userDb(userDb) {
    if (userDb) {
        connect(userDb, &UserDatabase::userLoggedIn, this, &LoginModel::onUserLoggedIn);
        connect(userDb, &UserDatabase::errorOccurred, this, &LoginModel::onError);
    }
}

// User functions

bool LoginModel::login(const std::string& username, const std::string& key) {
    if (!userDb) {
        emit loginError("UserDatabase not initialized.");
        return false;
    }

    QString qtUsername = QString::fromStdString(username);
    QString qtKey = QString::fromStdString(key);

    if (qtUsername.isEmpty() || qtKey.isEmpty()) {
        emit loginError("Username or key cannot be empty.");
        return false;
    }

    bool requestSent = userDb->login(qtUsername, qtKey);
    if (!requestSent) {
        emit loginError("Failed to initiate login request.");
        return false;
    }

    return true; 
}

bool LoginModel::signUp(const std::string& username, const std::string& key) {
    return true; 
}

bool LoginModel::changePassword(const std::string& username, const std::string& oldKey, const std::string& newKey) {
    return true; 
}

bool LoginModel::validateCredentials() {
    return true; 
}

UserData LoginModel::getUserData(const std::string& username) {
    UserData user;
    return user;
}

// File functions

std::vector<FileData> LoginModel::listOwnedFiles(const std::string& username) {
    std::vector<FileData> files;
    return files;
}

std::vector<FileData> LoginModel::listSharedFiles(const std::string& username) {
    std::vector<FileData> files;
    return files;
}

bool LoginModel::shareFile(const std::string& filename, const std::string& recipientUsername) {
    return true; 
}

bool LoginModel::revokeFile(const std::string& filename, const std::string& recipientUsername) {
    return true; 
}

bool LoginModel::deleteFile(const std::string& filename) {
    return true; 
}

bool LoginModel::uploadFile(const std::string& filename, const std::string& recipientUsername) {
    return true; 
}



