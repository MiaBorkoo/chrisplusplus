#ifndef DATABASE_H
#define DATABASE_H

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QTimer>

// Abstract base class for client-side API-based "database" handlers
class Database : public QObject {
    Q_OBJECT

public:
    explicit Database(QObject* parent = nullptr);
    virtual ~Database() = default;

    // Pure virtual functions that derived classes must implement
    virtual bool connect() = 0;
    virtual void disconnect() = 0;
    virtual void sync() = 0;
    virtual bool isReady() const = 0;
    virtual bool validateData(const QJsonObject& data) = 0;
    virtual void clearCache() = 0;

    // Common functionality for all database types
    bool isConnectionActive() const { return isConnected; }
    QString getLastError() const { return lastError; }
    QString getConnectionString() const { return connectionString; }
    
    // Auto-sync functionality
    void setAutoSync(bool enabled, int intervalMs = 30000);
    bool isAutoSyncEnabled() const { return autoSync; }

protected:
    // Protected members accessible to derived classes
    bool isConnected;
    QString connectionString;
    QString lastError;
    QTimer* syncTimer = nullptr;
    bool autoSync;

    // Protected helper methods for derived classes
    void setError(const QString& error);
    void setConnectionStatus(bool status);
    void setConnectionString(const QString& connStr);
    
    // Common validation helpers
    bool isValidString(const QString& str, int minLength = 1) const;
    bool isValidJson(const QJsonObject& json) const;

private slots:
    void performAutoSync();

signals:
    void errorOccurred(const QString& error);
    void connectionStatusChanged(bool connected);
    void syncCompleted(bool success);
    void dataValidated(bool isValid);
};

#endif // DATABASE_H