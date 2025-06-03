#pragma once
#include <QObject>
#include <QString>
#include <QJsonObject>
#include <memory>
#include "../sockets/SSLContext.h"
#include "../httpC/HttpClient.h"

// Uses HttpClient instead of QNetworkAccessManager
class Client : public QObject {
    Q_OBJECT
public:
    explicit Client(const QString& baseUrl, const QString& apiKey, QObject* parent = nullptr);
    
    void sendRequest(const QString& endpoint, const QString& method, const QJsonObject& data);

    void sendAsync(const QString& endpoint,
                    const QString& method,
                    const QJsonObject& payload,
                    std::function<void(int,const QJsonObject&)> onSuccess,
                    std::function<void(const QString&)>         onError);

signals:
    void responseReceived(int status, const QJsonObject& data);
    void networkError(const QString& error);

private:
    HttpRequest buildRequest(const QString& endpoint,
                                const QString& method,
                                const QJsonObject& payload);
    std::unique_ptr<SSLContext> m_sslContext;
    std::unique_ptr<HttpClient> m_http;
    QString m_baseUrl;
    QString m_apiKey;
}; 
