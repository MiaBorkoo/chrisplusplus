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

    if (!userDb->userExists(qtUsername)) {
        emit loginError("User does not exist.");
        return false;
    }

    bool requestSent = userDb->login(qtUsername, qtKey);
    if (!requestSent) {
        emit loginError("Failed to initiate login request.");
        return false;
    }
    return true; 
}

bool LoginModel::signUp(const std::string& username, const std::string& authSalt, const std::string& encSalt, const std::string& authKey, const std::string& encryptedMEK) {
    if (!userDb) {
        emit loginError("UserDatabase not initialized.");
        return false;
    }

    QString qtUsername = QString::fromStdString(username);
    QString qtAuthSalt = QString::fromStdString(authSalt);
    QString qtEncSalt = QString::fromStdString(encSalt);
    QString qtAuthKey = QString::fromStdString(authKey);
    QString qtEncryptedMEK = QString::fromStdString(encryptedMEK);

    if (qtUsername.isEmpty() || qtAuthSalt.isEmpty() || qtEncSalt.isEmpty() || qtAuthKey.isEmpty() || qtEncryptedMEK.isEmpty()) {
        emit loginError("Username or key cannot be empty.");
        return false;
    }

    if (userDb->userExists(qtUsername)) {
        emit loginError("User already exists.");
        return false;
    }

    bool requestSent = userDb->signUp(qtUsername, qtAuthSalt, qtEncSalt, qtAuthKey, qtEncryptedMEK);
    if (!requestSent) {
        emit loginError("Failed to initiate signup request.");
        return false;
    }
    return true; 
}

bool LoginModel::changePassword(const std::string& username, const std::string& oldAuthKey, const std::string& newAuthKey, const std::string& newEncryptedMEK) {
    if (!userDb) {
        emit loginError("UserDatabase not initialized.");
        return false;
    }

    QString qtUsername = QString::fromStdString(username);
    QString qtOldAuthKey = QString::fromStdString(oldAuthKey);
    QString qtNewAuthKey = QString::fromStdString(newAuthKey);
    QString qtNewEncryptedMEK = QString::fromStdString(newEncryptedMEK);

    if (qtUsername.isEmpty() || qtOldAuthKey.isEmpty() || qtNewAuthKey.isEmpty() || qtNewEncryptedMEK.isEmpty()) {
        emit loginError("Username or key cannot be empty.");
        return false;
    }

    bool requestSent = userDb->changePassword(qtUsername, qtOldAuthKey, qtNewAuthKey, qtNewEncryptedMEK);
    if (!requestSent) {
        emit loginError("Failed to initiate password change request.");
        return false;
    }
    return true; 
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



