#ifndef DATABASE_H
#define DATABASE_H

#include <QString>
#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>

// Forward declaration
class QSslError;

class Database : public QObject {
    Q_OBJECT

public:
    enum class DatabaseError {
        NoError,
        NetworkError,
        ServerError,
        TimeoutError,
        SslError
    };

    explicit Database(const QString& baseUrl, const QString& apiKey, QObject* parent = nullptr);
    virtual ~Database();

    virtual void setRequestTimeout(int milliseconds) = 0;

    // Utility methods 
    virtual DatabaseError getLastError() const = 0;
    virtual QString getLastErrorString() const = 0;

signals:
    void sslErrorOccurred(const QString& error);

protected slots:
    virtual void handleNetworkReply() = 0;
    virtual void handleSslErrors(QNetworkReply* reply, const QList<QSslError>& errors) = 0;
    virtual void handleTimeout() = 0;

protected:
    // Protected members for derived classes 
    QString baseUrl_;
    QString apiKey_;
    QNetworkAccessManager* networkManager_;
};

// Make enum available for Qt signals/slots
Q_DECLARE_METATYPE(Database::DatabaseError)

#endif // DATABASE_H