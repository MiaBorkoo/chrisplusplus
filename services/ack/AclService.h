#pragma once
#include <QObject>
#include <QStringList>
#include <memory>
#include "../../httpC/HttpClient.h"
#include "../../sockets/SSLContext.h"

class AclService : public QObject {
    Q_OBJECT
public:
    explicit AclService(QObject* parent = nullptr);
    void pushAcl(const QString& fileName, const QStringList& acl);

signals:
    void aclPushed(const QString& fileName);
    void errorOccurred(const QString& error);

private:
    SSLContext sslCtx_;
    std::shared_ptr<HttpClient> http_;
}; 