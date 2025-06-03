#include "AclService.h"
#include <QJsonDocument>
#include <QJsonArray>
#include <QUrl>

AclService::AclService(QObject* parent)
    : QObject(parent)
{
    http_ = std::make_shared<HttpClient>(sslCtx_, "api.myshare.com", "443");
}

void AclService::pushAcl(const QString& fileName, const QStringList& acl)
{
    QJsonObject body;
    body["acl"] = QJsonArray::fromStringList(acl);

    HttpRequest req;
    req.method = "PUT";
    req.path   = "/files/" +
                 QUrl::toPercentEncoding(fileName).toStdString() +
                 "/acl";
    req.headers["Content-Type"] = "application/json";
    req.body    = QJsonDocument(body).toJson(QJsonDocument::Compact).toStdString();

    http_->sendAsync(req,
        [this, fileName](const HttpResponse& r){
            if (r.statusCode == 200) emit aclPushed(fileName);
            else emit errorOccurred(
                QString("ACL push failed (%1)").arg(r.statusCode));
        },
        [this](const QString& err){ emit errorOccurred(err); });
} 