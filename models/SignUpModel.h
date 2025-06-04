#pragma once
#include <QObject>
#include <QString>
#include "../services/auth/IAuthService.h"

class SignUpModel : public QObject {
    Q_OBJECT

public:
    explicit SignUpModel(IAuthService* authDb, QObject* parent = nullptr);
    
    // User registration
    void registerUser(const QString& username, const QString& password, const QString& confirmPassword);

signals:
    void registrationSuccess();
    void registrationError(const QString& error);

public slots:
    void handleRegistrationCompleted(bool success);

private:
    IAuthService* m_authDb;
}; 