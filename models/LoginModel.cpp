#include "LoginModel.h"
#include "../utils/StringUtils.h"
#include <QDebug>

/**
 * @class LoginModel
 * @brief Manages login operations.
 * @author jjola00
 *
 * This class handles user login operations.
 */

LoginModel::LoginModel(std::shared_ptr<AuthService> authService, QObject* parent)
    : QObject(parent), m_authService(authService)
{
    connect(m_authService.get(), &AuthService::loginCompleted,
            this, &LoginModel::handleLoginCompleted);
    connect(m_authService.get(), &AuthService::errorOccurred,
            this, &LoginModel::handleError);
}

void LoginModel::login(const QString& username, const QString& password)
{
    // Store credentials for secure system initialization
    m_lastUsername = username;
    m_lastPassword = password;
    
    m_authService->login(username, password);
}

void LoginModel::handleLoginCompleted(bool success, const QString& token)
{
    if (success) {
        emit loginSuccess();
    } else {
        emit loginError("Login failed");
    }
}

void LoginModel::handleError(const QString& error)
{
    emit loginError(error);
}