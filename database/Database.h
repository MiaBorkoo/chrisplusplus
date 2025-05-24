#ifndef DATABASE_H
#define DATABASE_H

#include <QObject>

// Abstract base class for client-side API-based "database" handlers
class Database : public QObject {
    Q_OBJECT

public:
    virtual ~Database() = default;

    // Pure virtual function for optional syncing/caching
    virtual void sync() = 0;

protected:
    explicit Database(QObject* parent = nullptr) : QObject(parent) {}
};

#endif // DATABASE_H
#ifndef DATABASE_H
#define DATABASE_H

#include <QObject>

class Database : public QObject {
    Q_OBJECT

public:
    virtual ~Database() = default;

    // Pure virtual function for optional syncing/caching
    virtual void sync() = 0;

protected:
    explicit Database(QObject* parent = nullptr) : QObject(parent) {}
};

#endif // DATABASE_H
