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
    
    // Authentication
    void setAuthToken(const QString& token);
    
    // Access to shared HttpClient for file operations
    std::shared_ptr<HttpClient> getHttpClient() const;
    
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
    std::shared_ptr<HttpClient> httpClient_;
    QString baseUrl_;
    QString authToken_;  // Store auth token for secure requests
}; 
