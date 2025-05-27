 #pragma once
#include <QObject>
#include "../services/auth/IAuthService.h"

class LoginModel : public QObject {
    Q_OBJECT
public:
    explicit LoginModel(IAuthService* authDb = nullptr, QObject* parent = nullptr);

    Q_INVOKABLE void login(const QString& username, const QString& password);
    Q_INVOKABLE void registerUser(const QString& username,
                                const QString& password,
                                const QString& confirmPassword);
    Q_INVOKABLE void changePassword(const QString& username,
                                const QString& oldPassword,
                                const QString& newPassword,
                                const QString& confirmPassword);
    QString hashPassword(const QString& password, const QString& salt) const;

signals:
    void authSuccess();
    void authError(const QString& message);

private slots:
    void handleLoginCompleted(bool success, const QString& token);
    void handleRegistrationCompleted(bool success);

private:
    IAuthService* m_authDb;
};