#ifndef DATABASE_H
#define DATABASE_H

#include <QObject>
#include <QString>
#include <QJsonObject>

class Database : public QObject {
    Q_OBJECT
public:
    explicit Database(QObject* parent = nullptr) : QObject(parent) {}
    virtual ~Database() = default;

    virtual bool isReady() const = 0;
    virtual void clear() = 0;

signals:
    void errorOccurred(const QString& error);
};

#endif // DATABASE_H