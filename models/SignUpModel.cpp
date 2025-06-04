#include "SignUpModel.h"

/**
 * @class SignUpModel
 * @brief Manages user registration operations.
 * @author jjola00
 *
 * This class handles user registration operations.
 */

template <size_t N>
QString toBase64String(const std::array<uint8_t, N>& data) {
    return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
}

QString toBase64String(const std::vector<uint8_t>& data) {
    return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
}

SignUpModel::SignUpModel(std::shared_ptr<AuthService> authService, QObject* parent)
    : QObject(parent), m_authService(authService) 
{
    connect(m_authService.get(), &AuthService::registrationCompleted,
            this, &SignUpModel::handleRegistrationCompleted);
    connect(m_authService.get(), &AuthService::errorOccurred,
            this, &SignUpModel::handleError);
}

void SignUpModel::registerUser(const QString& username, 
                             const QString& password,
                             const QString& confirmPassword) {
    m_authService->registerUser(username, password, confirmPassword);
}

void SignUpModel::handleRegistrationCompleted(bool success) {
    if (success) {
        emit registrationSuccess();
    } else {
        emit registrationError("Registration failed");
    }
}

void SignUpModel::handleError(const QString& error) {
    emit registrationError(error);
} 