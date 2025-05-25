#pragma once
#include <QObject>
#include "../database/auth/AuthDatabaseInterface.h"

//class definition
class LoginModel : public QObject {
    Q_OBJECT
public:
    explicit LoginModel(AuthDatabaseInterface* authDb = nullptr, QObject* parent = nullptr);

    Q_INVOKABLE void login(const QString& username, const QString& password);
    Q_INVOKABLE void registerUser(const QString& username,
                                const QString& password);
    Q_INVOKABLE void changePassword(const QString& username,
                                const QString& oldPassword,
                                const QString& newPassword);
    Q_INVOKABLE void checkUserExists(const QString& username);

signals:
    void authSuccess();
    void authError(const QString& message);

private:
    AuthDatabaseInterface* m_authDb;
};