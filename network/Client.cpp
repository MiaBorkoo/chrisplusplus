#include "Client.h"
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QSslConfiguration>
#include <QRegularExpression>

/**
 * @class Client
 * @brief Handles network requests and responses.
 * @author jjola00
 *
 * This class sends requests to the server and handles responses.
 */

Client::Client(const QString& baseUrl, const QString& apiKey, QObject* parent) 
    : QObject(parent), m_baseUrl(baseUrl), m_apiKey(apiKey) 
{
    m_manager = new QNetworkAccessManager(this);
    m_manager->setTransferTimeout(30000);
}

void Client::sendRequest(const QString& endpoint,
                           const QString& method,
                           const QJsonObject& data) 
{
    // Input validation for endpoint and method
    QRegularExpression validEndpointRegex("^[a-zA-Z0-9/_-]+$"); // Adjust regex as needed
    if (!validEndpointRegex.match(endpoint).hasMatch()) {
        emit networkError("Invalid endpoint format");
        return;
    }

    // Validate method
    QStringList validMethods = {"GET", "POST", "PUT", "DELETE"};
    if (!validMethods.contains(method.toUpper())) {
        emit networkError("Unsupported HTTP method");
        return;
    }

    // Validate input data
    for (auto it = data.begin(); it != data.end(); ++it) {
        if (it.key().length() > 100 || it.value().toString().length() > 255) { // Example length checks
            emit networkError("Input exceeds maximum length");
            return;
        }
        // Sanitize input
        QRegularExpression validInputRegex("^[a-zA-Z0-9_\\-\\.]+$"); // Adjust regex as needed
        if (!validInputRegex.match(it.value().toString()).hasMatch()) {
            emit networkError("Invalid input detected");
            return;
        }
    }

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
            QString errorMsg = reply->errorString();
            if (reply->error() == QNetworkReply::TimeoutError) {
                errorMsg = "Request timed out. Please try again.";
            } else if (reply->error() == QNetworkReply::HostNotFoundError) {
                errorMsg = "Server not found. Please check your network connection.";
            }
            emit networkError(errorMsg);
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