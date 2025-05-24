#ifndef AUTH_CLIENT_H
#define AUTH_CLIENT_H

#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <QSslError>

class AuthClient : public QObject {
    Q_OBJECT

public:
    enum class RequestType {
        Register,
        Login,
        ChangePassword,
        UserExists
    };

    AuthClient(const QString& baseUrl, const QString& apiKey, QObject* parent = nullptr);
    
    // User functions
    void registerUser(const QString& username, const QString& authSalt, 
                      const QString& encSalt, const QString& authKey, 
                      const QString& encryptedMEK);
    
    void login(const QString& username, const QString& authKey);
    
    void changePassword(const QString& username, const QString& oldAuthKey, 
                        const QString& newAuthKey, const QString& newEncryptedMEK);
    bool userExists(const QString& username);

    QString getSessionToken() const;
    bool hasValidSession() const;
    void clearSession();

private slots:
    void handleNetworkReply();
    void handleSslErrors(QNetworkReply* reply, const QList<QSslError>& errors);

private:
    QString baseUrl;
    QString apiKey;
    QString currentSessionToken;
    QNetworkAccessManager* networkManager;

    void performRequest(const QString& url, const QString& method, const QJsonObject& data, RequestType type);

signals:
    void registrationCompleted(bool success);
    void registrationFailed(const QString& error);
    void loginCompleted(bool success);
    void loginFailed(const QString& error);
    void passwordChangeCompleted(bool success);
    void passwordChangeFailed(const QString& error);
    void sslErrorOccurred(const QString& error);

};

#endif // AUTH_CLIENT_H