#include "Database.h"
#include <QDebug>
#include <QTimer>

Database::Database(QObject* parent)
    : QObject(parent) {
    syncTimer = new QTimer(this);
    syncTimer->setSingleShot(false);
    connect(syncTimer, &QTimer::timeout, this, &Database::performAutoSync);
    qDebug() << "Database base class initialized";
}

void Database::setAutoSync(bool enabled, int intervalMs) {
    autoSync = enabled;
    if (autoSync && intervalMs > 0) {
        syncTimer->setInterval(intervalMs);
        syncTimer->start();
        qDebug() << "Auto-sync enabled with interval:" << intervalMs << "ms";
    } else {
        syncTimer->stop();
        qDebug() << "Auto-sync disabled";
    }
}

void Database::setError(const QString& error) {
    lastError = error;
    qWarning() << "Database error:" << error;
    emit errorOccurred(error);
}

bool Database::isValidString(const QString& str, int minLength) const {
    return !str.trimmed().isEmpty() && str.length() >= minLength;
}

bool Database::isValidJson(const QJsonObject& json) const {
    return !json.isEmpty();
}

void Database::performAutoSync() {
    if (autoSync) {
        qDebug() << "Performing auto-sync...";
        emit syncCompleted(true); 
    }
}