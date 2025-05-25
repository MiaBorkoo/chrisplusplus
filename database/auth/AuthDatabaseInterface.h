#pragma once
#include "../Database.h"
#include <QString>

class AuthDatabaseInterface : public Database {
    Q_OBJECT
public:
    virtual ~AuthDatabaseInterface() = default;
    
    virtual void login(const QString& username, 
                     const QString& authKey) = 0;
                     
    virtual void registerUser(const QString& username,
                            const QString& authSalt,
                            const QString& encSalt,
                            const QString& authKey,
                            const QString& encryptedMEK) = 0;
                            
    virtual void changePassword(const QString& username,
                              const QString& oldAuthKey,
                              const QString& newAuthKey,
                              const QString& newEncryptedMEK) = 0;
                              
    virtual void checkUserExists(const QString& username) = 0;

signals:
    void loginCompleted(bool success, const QString& token);
    void registrationCompleted(bool success);
    void passwordChangeCompleted(bool success);
    void userExistsChecked(bool exists);
};