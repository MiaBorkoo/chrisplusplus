#pragma once
#include <QObject>
#include "../database/auth/AuthDatabaseInterface.h"

class LoginModel : public QObject {
    Q_OBJECT
public:
    explicit LoginModel(AuthDatabaseInterface* authDb, QObject* parent = nullptr);

    Q_INVOKABLE void login(const QString& username, const QString& password);
    Q_INVOKABLE void registerUser(const QString& username,
                                const QString& password);

signals:
    void authSuccess();
    void authError(const QString& message);

private:
    AuthDatabaseInterface* m_authDb;
};