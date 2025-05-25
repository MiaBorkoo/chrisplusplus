#include "AuthClient.h"
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QSslConfiguration>

AuthClient::AuthClient(const QString& baseUrl, const QString& apiKey, QObject* parent) 
    : QObject(parent), m_baseUrl(baseUrl), m_apiKey(apiKey) 
{
    m_manager = new QNetworkAccessManager(this);
    m_manager->setTransferTimeout(30000);
}

void AuthClient::sendRequest(const QString& endpoint,
                           const QString& method,
                           const QJsonObject& data) 
{
    QUrl url(m_baseUrl + endpoint);
    QNetworkRequest request(url);
    
    request.setRawHeader("Authorization", ("Bearer " + m_apiKey).toUtf8());
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    // SSL Configuration
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setProtocol(QSsl::TlsV1_2OrLater);
    request.setSslConfiguration(sslConfig);

    QNetworkReply* reply = nullptr;
    QJsonDocument doc(data);

    if (method.compare("GET", Qt::CaseInsensitive) == 0) {
        QUrlQuery query;
        for(auto it = data.begin(); it != data.end(); ++it) {
            query.addQueryItem(it.key(), it.value().toString());
        }
        url.setQuery(query);
        request.setUrl(url);
        reply = m_manager->get(request);
    }
    else if (method.compare("POST", Qt::CaseInsensitive) == 0) {
        reply = m_manager->post(request, doc.toJson());
    }
    else if (method.compare("PUT", Qt::CaseInsensitive) == 0) {
        reply = m_manager->put(request, doc.toJson());
    }
    else if (method.compare("DELETE", Qt::CaseInsensitive) == 0) {
        reply = m_manager->deleteResource(request);
    }
    else {
        emit networkError("Unsupported HTTP method");
        return;
    }

    connect(reply, &QNetworkReply::finished, [=]() {
        if (reply->error() == QNetworkReply::NoError) {
            emit responseReceived(
                reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(),
                QJsonDocument::fromJson(reply->readAll()).object()
            );
        } else {
            emit networkError(reply->errorString());
        }
        reply->deleteLater();
    });

    connect(reply, &QNetworkReply::sslErrors, [=](const QList<QSslError>& errors) {
        QString errorMsg;
        for (const auto& error : errors) {
            errorMsg += error.errorString() + "\n";
        }
        emit networkError("SSL Errors: " + errorMsg);
    });
}