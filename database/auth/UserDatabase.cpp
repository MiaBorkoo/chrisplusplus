#include "UserDatabase.h"

UserDatabase::UserDatabase(AuthClient* client, QObject* parent)
    : AuthDatabaseInterface(parent), m_client(client) {
    connect(m_client, &AuthClient::responseReceived,
            this, &UserDatabase::handleLoginResponse);
}

void UserDatabase::login(const QString& username, const QString& authKey) {
    QJsonObject data{
        {"username", username},
        {"auth_key", authKey}
    };
    m_client->sendRequest("/login", "POST", data);
}

void UserDatabase::handleLoginResponse(int status, const QJsonObject& data) {
    if (status == 200) {
        m_sessionToken = data["token"].toString();
        emit loginCompleted(true, m_sessionToken);
    } else {
        emit errorOccurred(data["error"].toString());
        emit loginCompleted(false, "");
    }
}