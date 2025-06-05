#include "Client.h"
#include <QJsonDocument>
#include <QUrl>
#include <QDebug>

/**
 * @brief Clean network client for JSON API requests over HTTPS
 * @author jj
 * 
 * This class provides simple, secure JSON communication with REST APIs.
 * Socket optimizations are automatically applied by the underlying SSL/HTTP layers.
 */

Client::Client(const QString& baseUrl, QObject* parent) 
    : QObject(parent), baseUrl_(baseUrl)
{
    // Initialize SSL infrastructure
    SSLContext::initializeOpenSSL();
    sslContext_ = std::make_unique<SSLContext>();
    
    // Extract host and port from URL
    QUrl url(baseUrl);
    std::string host = url.host().toStdString();
    std::string port = QString::number(url.port(443)).toStdString();
    
    // Create HTTP client with automatic optimizations
    httpClient_ = std::make_shared<HttpClient>(*sslContext_, host, port);
    
    qDebug() << "Client initialized for:" << baseUrl;
}

std::shared_ptr<HttpClient> Client::getHttpClient() const {
    return httpClient_;
}

void Client::setAuthToken(const QString& token) {
    authToken_ = token;
    qDebug() << "Client::setAuthToken called with token:" << token.left(20) + "...";
}

HttpRequest Client::buildRequest(const QString& endpoint,
                                const QString& method,
                                const QJsonObject& payload)
{
    HttpRequest request;
    request.method = method.toStdString();
    request.path = endpoint.toStdString();

    // Set standard headers
    QUrl url(baseUrl_);
    request.headers["Host"] = url.host().toStdString();
    request.headers["User-Agent"] = "ChrisPlusPlus/1.0";
    request.headers["Content-Type"] = "application/json";
    request.headers["Accept"] = "application/json";
    
    // Add Authorization header if token is available
    if (!authToken_.isEmpty()) {
        request.headers["Authorization"] = ("Bearer " + authToken_).toStdString();
        qDebug() << "Added Authorization header for" << endpoint << "with token:" << authToken_.left(20) + "...";
    } else {
        qDebug() << "No auth token available for" << endpoint;
    }

    // Add JSON body for POST/PUT requests
    if (method.compare("POST", Qt::CaseInsensitive) == 0 ||
        method.compare("PUT", Qt::CaseInsensitive) == 0) {
        if (!payload.isEmpty()) {
            QJsonDocument doc(payload);
            request.body = doc.toJson(QJsonDocument::Compact).toStdString();
        }
    }

    return request;
}

void Client::sendRequest(const QString& endpoint, 
                        const QString& method, 
                        const QJsonObject& data)
{
    try {
        HttpRequest request = buildRequest(endpoint, method, data);
        HttpResponse response = httpClient_->sendRequest(request);

        // Parse JSON response
        QJsonObject responseObj;
        if (!response.body.empty()) {
            QJsonParseError parseError;
            QJsonDocument doc = QJsonDocument::fromJson(
                QByteArray::fromStdString(response.body), &parseError);
            
            if (parseError.error == QJsonParseError::NoError) {
                responseObj = doc.object();
            } else {
                qWarning() << "JSON parse error:" << parseError.errorString();
                qWarning() << "Parse error offset:" << parseError.offset;
                responseObj["error"] = "Invalid JSON response";
            }
        }
        
        responseObj["endpoint"] = endpoint;
        emit responseReceived(response.statusCode, responseObj);
        
    } catch (const std::exception& ex) {
        emit networkError(QString::fromUtf8(ex.what()));
    }
}

void Client::sendAsync(const QString& endpoint,
                      const QString& method,
                      const QJsonObject& payload,
                      std::function<void(int, const QJsonObject&)> onSuccess,
                      std::function<void(const QString&)> onError)
{
    HttpRequest request = buildRequest(endpoint, method, payload);
    
    httpClient_->sendAsync(request,
        // Success callback
        [this, endpoint, onSuccess](const HttpResponse& response) {
            QJsonObject responseObj;
            if (!response.body.empty()) {
                QJsonParseError parseError;
                QJsonDocument doc = QJsonDocument::fromJson(
                    QByteArray::fromStdString(response.body), &parseError);
                
                if (parseError.error == QJsonParseError::NoError) {
                    responseObj = doc.object();
                } else {
                    qWarning() << "JSON parse error:" << parseError.errorString();
                    qWarning() << "Parse error offset:" << parseError.offset;
                    responseObj["error"] = "Invalid JSON response";
                }
            }
            
            responseObj["endpoint"] = endpoint;
            
            // Emit signal
            emit responseReceived(response.statusCode, responseObj);
            
            // Call callback if provided
            if (onSuccess) {
                onSuccess(response.statusCode, responseObj);
            }
        },
        // Error callback
        [this, onError](const QString& error) {
            emit networkError(error);
            if (onError) {
                onError(error);
            }
        }
    );
}
