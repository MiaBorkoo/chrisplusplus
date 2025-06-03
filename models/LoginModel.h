#pragma once
#include <QObject>
#include <QString>
#include <memory>
#include "auth/IAuthService.h"

//im sorry jjola00 for modifying all of ur code its back now kill me
// Forward declaration
class AuthService;

class LoginModel : public QObject {
    Q_OBJECT

public:
    explicit LoginModel(IAuthService* authDb, QObject* parent = nullptr);
    
    //  Core authentication
    void login(const QString& username, const QString& password);
    void registerUser(const QString& username, const QString& password, const QString& confirmPassword);
    
    void changePassword(const QString& username, const QString& oldPassword,
                       const QString& newPassword, const QString& confirmPassword);


signals:
    void authSuccess();
    void authError(const QString& error);

public slots: //or private??? idk 
    void handleLoginCompleted(bool success, const QString& token);
    void handleRegistrationCompleted(bool success);

private:
    IAuthService* m_authDb;
    
    QString hashPassword(const QString& password, const QString& salt) const;
};