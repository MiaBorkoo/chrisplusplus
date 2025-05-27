#pragma once
#include <QObject>

class ApiService : public QObject {
    Q_OBJECT
public:
    explicit ApiService(QObject* parent = nullptr) : QObject(parent) {}
    virtual ~ApiService() = default;

signals:
    void errorOccurred(const QString& error);
}; 
