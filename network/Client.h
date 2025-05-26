#pragma once
#include <QObject>
#include <QString>
#include <QJsonObject>
#include <memory>
#include "../sockets/SSLContext.h"
#include "../httpC/HttpClient.h"

// ✅ SECURE: Uses YOUR HttpClient instead of QNetworkAccessManager
class Client : public QObject {
    Q_OBJECT
public:
    explicit Client(const QString& baseUrl, const QString& apiKey, QObject* parent = nullptr);
    
    void sendRequest(const QString& endpoint, const QString& method, const QJsonObject& data);

signals:
    void responseReceived(int status, const QJsonObject& data);
    void networkError(const QString& error);

private:
    std::unique_ptr<SSLContext> m_sslContext;
    std::unique_ptr<HttpClient> m_httpClient;
    QString m_baseUrl;
    QString m_apiKey;
}; 