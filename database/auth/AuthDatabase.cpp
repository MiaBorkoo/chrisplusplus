#include "AuthDatabase.h"

AuthDatabase::AuthDatabase(AuthClient* client, QObject* parent)
    : AuthDatabaseInterface(parent), m_client(client) {
    connect(m_client, &AuthClient::responseReceived,
            this, &AuthDatabase::handleLoginResponse);
}

void AuthDatabase::login(const QString& username, const QString& authKey) {
    QJsonObject data{
        {"username", username},
        {"auth_key", authKey}
    };
    m_client->sendRequest("/login", "POST", data);
}

void AuthDatabase::handleLoginResponse(int status, const QJsonObject& data) {
    if (status == 200) {
        m_sessionToken = data["token"].toString();
        emit loginCompleted(true, m_sessionToken);
    } else {
        emit errorOccurred(data["error"].toString());
        emit loginCompleted(false, "");
    }
}