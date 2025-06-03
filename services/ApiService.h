#pragma once
#include <QObject>
#include <QString>

class ApiService : public QObject {
    Q_OBJECT
public:
    explicit ApiService(QObject* parent = nullptr) : QObject(parent) {}
    virtual ~ApiService() = default;

    virtual bool isInitialized() const = 0;

signals:
    void errorOccurred(const QString& error);

protected:
    void reportError(const QString& error) {
        emit errorOccurred(error);
    }
}; 