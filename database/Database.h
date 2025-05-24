#ifndef DATABASE_H
#define DATABASE_H

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QCache>

class Database : public QObject {
    Q_OBJECT

public:
    explicit Database(QObject* parent = nullptr);
    virtual ~Database() = default;

    virtual bool isReady() const = 0;
    virtual bool validateData(const QJsonObject& data) = 0;
    virtual void clearCache() = 0;

    QString getLastError() const { return lastError; }
    bool isAutoSyncEnabled() const { return autoSync; }

    //default value
    void setAutoSync(bool enabled, int intervalMs = 30000);

protected:
    void setError(const QString& error);

    // Validation helpers
    bool isValidString(const QString& str, int minLength = 1) const;
    bool isValidJson(const QJsonObject& json) const;

    QCache<QString, QJsonObject> responseCache;

private slots:
    void performAutoSync();

private:
    QString lastError;
    QTimer* syncTimer = nullptr;
    bool autoSync = false;

signals:
    void errorOccurred(const QString& error);
    void syncCompleted(bool success); 
    void dataValidated(bool isValid);
};

#endif // DATABASE_H