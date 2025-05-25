#pragma once
#include <QObject>
#include <QNetworkAccessManager>

class AuthClient : public QObject {
    Q_OBJECT
public:                                                                 //default arguement
    explicit AuthClient(const QString& baseUrl, const QString& apiKey, QObject* parent = nullptr);
    
    void sendRequest(const QString& endpoint, const QString& method, const QJsonObject& data);

signals:
    void responseReceived(int status, const QJsonObject& data);
    void networkError(const QString& error);

private:
    QNetworkAccessManager* m_manager;
    QString m_baseUrl;
    QString m_apiKey;
};