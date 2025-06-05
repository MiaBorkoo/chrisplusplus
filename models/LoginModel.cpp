#include "LoginModel.h"
#include <QDebug>

/**
 * @class LoginModel
 * @brief Manages login operations.
 * @author jjola00
 *
 * This class handles user login operations.
 */

namespace {
    template <size_t N>
    QString toBase64String(const std::array<uint8_t, N>& data) {
        return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
    }

    QString toBase64String(const std::vector<uint8_t>& data) {
        return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
    }
}

LoginModel::LoginModel(std::shared_ptr<AuthService> authService, QObject* parent)
    : QObject(parent), m_authService(authService) 
{
    connect(m_authService.get(), &AuthService::loginCompleted,
            this, &LoginModel::handleLoginCompleted);
    connect(m_authService.get(), &AuthService::errorOccurred,
            this, &LoginModel::handleError);
}

void LoginModel::login(const QString& username, const QString& password) {
    if (username.isEmpty() || password.isEmpty()) {
        emit loginError("Credentials cannot be empty");
        return;
    }
    m_authService->login(username, password);
}

void LoginModel::handleLoginCompleted(bool success, const QString& token) {
    if (success) {
        emit loginSuccess();
    } else {
        emit loginError("Login failed");
    }
}

void LoginModel::handleError(const QString& error) {
    emit loginError(error);
}