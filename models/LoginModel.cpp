#include "LoginModel.h"
#include "../crypto/KeyDerivation.h"
#include "../crypto/AuthHash.h"

/**
 * @class LoginModel
 * @brief Manages login operations.
 * @author jjola00
 *
 * This class handles user login operations.
 */

template <size_t N>
QString toBase64String(const std::array<uint8_t, N>& data) {
    return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
}

QString toBase64String(const std::vector<uint8_t>& data) {
    return QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size())).toBase64());
}

LoginModel::LoginModel(IAuthService* authDb, QObject* parent)
    : QObject(parent), m_authDb(authDb) 
{
    connect(m_authDb, &IAuthService::loginCompleted,
            this, &LoginModel::handleLoginCompleted);
}

void LoginModel::handleLoginCompleted(bool success, const QString& token) {
    if (success) {
        emit loginSuccess();
    } else {
        emit loginError("Login failed");
    }
}

void LoginModel::login(const QString& username, const QString& password) {
    if (username.isEmpty() || password.isEmpty()) {
        emit loginError("Credentials cannot be empty");
        return;
    }

    try {
        // 1. Get salts from server (this would be a separate API call)
        // TODO: Implement salt retrieval
        std::vector<uint8_t> authSalt1; // = getSaltsFromServer(username).authSalt1;
        std::vector<uint8_t> authSalt2; // = getSaltsFromServer(username).authSalt2;
        std::vector<uint8_t> encSalt;   // = getSaltsFromServer(username).encSalt;

        // 2. Derive keys using the same process as registration
        KeyDerivation kd;
        DerivedKeys keys = kd.deriveKeysFromPassword(password.toStdString(), authSalt1, encSalt);

        // 3. Generate auth hash using server auth key and second salt
        std::vector<uint8_t> serverAuthKeyVec(keys.serverAuthKey.begin(), keys.serverAuthKey.end());
        std::vector<uint8_t> authHash = AuthHash::computeAuthHash(serverAuthKeyVec, authSalt2);

        // 4. Convert to base64 and send to server
        QString authHashB64 = toBase64String(authHash);
        m_authDb->login(username, authHashB64);
    } catch (const std::exception& e) {
        emit loginError(QString("Login failed: %1").arg(e.what()));
    }
}