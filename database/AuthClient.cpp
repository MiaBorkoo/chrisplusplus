#include "AuthClient.h"
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QUrl>
#include <QUrlQuery>
#include <QTimer>

AuthClient::AuthClient(const QString& baseUrl, const QString& apiKey, QObject* parent) : QObject(parent), baseUrl(baseUrl), apiKey(apiKey) {
    networkManager = new QNetworkAccessManager(this);
    networkManager->setTransferTimeout(30000);
}

void AuthClient::registerUser(const QString& username, const QString& authSalt, 
                               const QString& encSalt, const QString& authKey, 
                               const QString& encryptedMEK) {
    QJsonObject data;
    data["username"] = username;
    data["auth_salt"] = authSalt;
    data["enc_salt"] = encSalt;
    data["auth_key"] = authKey;
    data["encrypted_mek"] = encryptedMEK;

    QString url = baseUrl + "/register";
    performRequest(url, "POST", data, RequestType::Register);
}

void AuthClient::login(const QString& username, const QString& authKey) {
    QJsonObject data;
    data["username"] = username;
    data["auth_key"] = authKey;

    QString url = baseUrl + "/login";
    performRequest(url, "POST", data, RequestType::Login);
}

void AuthClient::changePassword(const QString& username, const QString& oldAuthKey, 
                                 const QString& newAuthKey, const QString& newEncryptedMEK) {
    QJsonObject data;
    data["username"] = username;
    data["old_auth_key"] = oldAuthKey;
    data["new_auth_key"] = newAuthKey;
    data["new_encrypted_mek"] = newEncryptedMEK;

    QString url = baseUrl + "/change_password";
    performRequest(url, "POST", data, RequestType::ChangePassword);
}

bool AuthClient::userExists(const QString& username) {
    QJsonObject data;
    data["username"] = username;

    QString url = baseUrl + "/user_exists";
    performRequest(url, "GET", data, RequestType::UserExists);
    return true;
}

//function to perform requests
void AuthClient::performRequest(const QString& url, const QString& method, const QJsonObject& data, RequestType type) {
    //converts str url to QUrl
    QNetworkRequest request(QUrl(url));
    request.setRawHeader("Authorization", ("Bearer " + apiKey).toUtf8());
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    //ssl config
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setProtocol(QSsl::TlsV1_20rLater);
    request.setSslConfiguration(sslConfig);
    
    //network reply
    QNetworkReply* reply = nullptr;
    if (method == "POST") {
        QJsonDocument doc(data);
        reply = networkManager->post(request, doc.toJson());
    } else if (method == "GET") {
        reply = networkManager->get(request);
    } else if (method == "PUT") {
        QJsonDocument doc(data);
        reply = networkManager->put(request, doc.toJson());
    } else if (method == "DELETE") {
        reply = networkManager->deleteResource(request);
    }

    if (reply) {
        reply->setProperty("requestType", static_cast<int>(type));

        connect(reply, &QNetworkReply::finished, this, &AuthClient::handleNetworkReply);
        connect(reply, &QNetworkReply::sslErrors, this, &AuthClient::handleSslErrors);        
    }
}

void AuthClient::handleNetworkReply() {
    //dynamic cast(but for Qt) sender to QNetworkReply
    QNetworkReply* reply = qobject_cast<QNetworkReply*>(sender());
    if (!reply) return;

    //Gets stored request type from performRequest()
    RequestType type = static_cast<RequestType>(reply->property("requestType").toInt());
    
    if (reply->error() == QNetworkReply::NoError) {
        QByteArray responseData = reply->readAll();
        QJsonDocument jsonResponse = QJsonDocument::fromJson(responseData);
        QJsonObject responseObj = jsonResponse.object();
        
        switch (type) {
            case RequestType::Login: {
                //checks if session token(might change later idk) is empty
                QString sessionToken = responseObj["session_token"].toString();
                if (!sessionToken.isEmpty()) {
                    emit loginCompleted(sessionToken);
                } else {
                    emit loginFailed("Login Failed");
                }
                break;
            }
            case RequestType::Register: {
                bool success = responseObj["success"].toBool(false);
                if (success) {
                    emit registrationCompleted(true);
                } else {
                    QString error = responseObj["error"].toString("Registration failed");
                    emit registrationFailed(error);
                }
                break;
            }
            case RequestType::ChangePassword: {
                bool success = responseObj["success"].toBool(false);
                if (success) {
                    emit passwordChangeCompleted(true);
                } else {
                    QString error = responseObj["error"].toString("Password change failed");
                    emit passwordChangeFailed(error);
                }
                break;
            }
        }
    } else {
        QString errorString = reply->errorString();
        
        switch (type) {
            case RequestType::Login:
                emit loginFailed(errorString);
                break;
            case RequestType::Register:
                emit registrationFailed(errorString);
                break;
            case RequestType::ChangePassword:
                emit passwordChangeFailed(errorString);
                break;
        }
    }
    //delete reply safely
    reply->deleteLater();
}
void AuthClient::handleSslErrors(QNetworkReply* reply, const QList<QSslError>& errors) {
    // Log SSL errors for debugging
    for (const QSslError& error : errors) {
        qWarning() << "SSL Error:" << error.errorString();
    }
    reply->ignoreSslErrors();
    
    emit sslErrorOccurred("SSL connection error occurred");
}