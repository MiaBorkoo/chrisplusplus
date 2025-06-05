#pragma once
#include <QObject>
#include <QString>
#include <QJsonObject>
#include <memory>
#include "../sockets/SSLContext.h"
#include "../httpC/HttpClient.h"

/**
 * @brief Clean network client for JSON API requests over HTTPS
 * @author jj
 * 
 * Simple client for secure JSON communication with REST APIs.
 * Socket optimizations are handled automatically by the underlying layers.
 */
class Client : public QObject {
    Q_OBJECT
    
public:
    explicit Client(const QString& baseUrl, QObject* parent = nullptr);
    
    // Synchronous requests
    void sendRequest(const QString& endpoint, const QString& method, const QJsonObject& data = {});
    
    // Asynchronous requests
    void sendAsync(const QString& endpoint,
                   const QString& method,
                   const QJsonObject& payload = {},
                   std::function<void(int, const QJsonObject&)> onSuccess = nullptr,
                   std::function<void(const QString&)> onError = nullptr);

signals:
    void responseReceived(int statusCode, const QJsonObject& data);
    void networkError(const QString& error);

private:
    HttpRequest buildRequest(const QString& endpoint,
                           const QString& method,
                           const QJsonObject& payload);
    
    std::unique_ptr<SSLContext> sslContext_;
    std::unique_ptr<HttpClient> httpClient_;
    QString baseUrl_;
}; 
