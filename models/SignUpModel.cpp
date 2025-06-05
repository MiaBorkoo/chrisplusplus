#include "SignUpModel.h"
#include "../utils/StringUtils.h"
#include <QDebug>

/**
 * @class SignUpModel
 * @brief Manages user registration operations.
 * @author jjola00
 *
 * This class handles user registration operations.
 */

SignUpModel::SignUpModel(std::shared_ptr<AuthService> authService, QObject* parent)
    : QObject(parent), m_authService(authService)
{
    connect(m_authService.get(), &AuthService::registrationCompleted,
            this, &SignUpModel::handleRegistrationCompleted);
    connect(m_authService.get(), &AuthService::errorOccurred,
            this, &SignUpModel::handleError);
}

void SignUpModel::registerUser(const QString& username, const QString& password, const QString& confirmPassword)
{
    if (password != confirmPassword) {
        emit registrationError("Passwords do not match");
        return;
    }

    m_authService->registerUser(username, password, confirmPassword);
}

void SignUpModel::handleRegistrationCompleted(bool success)
{
    if (success) {
        emit registrationSuccess();
    } else {
        emit registrationError("Registration failed");
    }
}

void SignUpModel::handleError(const QString& error)
{
    emit registrationError(error);
} 