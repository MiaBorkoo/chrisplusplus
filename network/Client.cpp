#include "Client.h"
#include <QJsonDocument>
#include <QUrl>
#include <stdexcept>

Client::Client(const QString& baseUrl, const QString& apiKey, QObject* parent) 
    : QObject(parent), m_baseUrl(baseUrl), m_apiKey(apiKey)
{
    // ✅ SECURE: Use YOUR SSL infrastructure
    SSLContext::initializeOpenSSL();
    m_sslContext = std::make_unique<SSLContext>();
    
    // Extract host and port from baseUrl
    QUrl url(baseUrl);
    std::string host = url.host().toStdString();
    std::string port = QString::number(url.port(443)).toStdString();
    
    m_httpClient = std::make_unique<HttpClient>(*m_sslContext, host, port);
}

void Client::sendRequest(const QString& endpoint, const QString& method, const QJsonObject& data) {
    try {
        // Build HTTP request using YOUR HttpRequest
        HttpRequest request;
        request.method = method.toStdString();
        request.path = endpoint.toStdString();
        
        // Add headers
        QUrl url(m_baseUrl);
        request.headers["Host"] = url.host().toStdString();
        request.headers["User-Agent"] = "ChrisPlusPlus-Auth/1.0";
        request.headers["Content-Type"] = "application/json";
        
        if (!m_apiKey.isEmpty()) {
            request.headers["Authorization"] = ("Bearer " + m_apiKey).toStdString();
        }
        
        // Add JSON body for POST/PUT
        if (method.compare("POST", Qt::CaseInsensitive) == 0 || 
            method.compare("PUT", Qt::CaseInsensitive) == 0) {
            QJsonDocument doc(data);
            request.body = doc.toJson(QJsonDocument::Compact).toStdString();
        }
        
        // ✅ SECURE: Send via YOUR HttpClient (SSL encrypted)
        HttpResponse response = m_httpClient->sendRequest(request);
        
        // Parse JSON response
        QJsonDocument responseDoc = QJsonDocument::fromJson(QByteArray::fromStdString(response.body));
        QJsonObject responseObj = responseDoc.object();
        
        // Add endpoint info for routing
        responseObj["endpoint"] = endpoint;
        
        emit responseReceived(response.statusCode, responseObj);
        
    } catch (const std::exception& e) {
        emit networkError(QString::fromStdString(e.what()));
    }
} 