#ifndef USER_DATABASE_H
#define USER_DATABASE_H

#include "Database.h"
#include <QJsonObject>
#include <QTimer>

class UserDatabase : public Database {
    Q_OBJECT

public:
    // Enum for request types
    enum class RequestType {
        FetchSalts,
        FetchUserData
    };

    // Struct to hold user data
    struct UserData {
        QString username;
        QString authSalt;
        QString encSalt;
        QString authKey;
        QString encryptedMEK;
        QString createdAt;
    };

    // Constructor
    explicit UserDatabase(const QString& baseUrl = "https://SQL.GOBBLER.INFO",
                          const QString& apiKey = "",
                          QObject* parent = nullptr);
    // Destructor
    ~UserDatabase() override;

    // Prevent copying, allow moving
    UserDatabase(const UserDatabase&) = delete;
    UserDatabase& operator=(const UserDatabase&) = delete;
    UserDatabase(UserDatabase&& other) noexcept;
    UserDatabase& operator=(UserDatabase&& other) noexcept;

    // Implement pure virtual methods from Database
    void setRequestTimeout(int milliseconds) override;
    DatabaseError getLastError() const override { return lastError_; }
    QString getLastErrorString() const override { return lastErrorString_; }

    // User-specific methods
    void fetchSaltsAsync(const QString& username); // Maps to GET /api/auth/{username}/salts
    void fetchUserDataAsync(const QString& username);

    // Synchronous methods (use sparingly)
    bool fetchSaltsSync(const QString& username, QString& authSalt, QString& encSalt, int timeoutMs = 5000);
    UserData fetchUserDataSync(const QString& username, int timeoutMs = 5000);

signals:
    // Success signals
    void saltsFetched(const QString& username, const QString& authSalt, const QString& encSalt);
    void userDataFetched(const QString& username, const UserData& userData);

    // Error signals
    void saltsFetchFailed(const QString& username, DatabaseError error, const QString& message);
    void userDataFetchFailed(const QString& username, DatabaseError error, const QString& message);

private slots:
    // Implement slots from Database
    void handleNetworkReply() override;
    void handleSslErrors(QNetworkReply* reply, const QList<QSslError>& errors) override;
    void handleTimeout() override;

private:
    int requestTimeout_;
    DatabaseError lastError_;
    QString lastErrorString_;

    // Active request tracking
    struct ActiveRequest {
        RequestType type;
        QString username;
        QTimer* timeoutTimer;
    };
    QHash<QNetworkReply*, ActiveRequest> activeRequests_;

    // Helper methods
    void performRequest(const QString& endpoint, const QString& method,
                        const QJsonObject& data, RequestType type,
                        const QString& username);
    UserData parseUserData(const QJsonObject& json) const;
    void setError(DatabaseError error, const QString& message);
    bool waitForReply(QNetworkReply* reply, int timeoutMs);
    void cleanupRequest(QNetworkReply* reply);
};

// Make struct available for Qt signals/slots
Q_DECLARE_METATYPE(UserDatabase::UserData)

#endif // USER_DATABASE_H