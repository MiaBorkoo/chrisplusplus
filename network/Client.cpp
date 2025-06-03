#include "Client.h"
#include <QJsonDocument>
#include <QUrl>

/**
 * @class Client
 * @brief Handles network requests and responses.
 * @author jjola00
 *
 * This class sends requests to the server and handles responses.
 */

Client::Client(const QString& baseUrl, const QString& apiKey, QObject* parent) 
    : QObject(parent), m_baseUrl(baseUrl), m_apiKey(apiKey)
{
    // uses SSL infrastructure
    SSLContext::initializeOpenSSL();
    m_sslContext = std::make_unique<SSLContext>();
    
    // Extract host and port from baseUrl
    QUrl url(baseUrl);
    std::string host = url.host().toStdString();
    std::string port = QString::number(url.port(443)).toStdString();
    
    m_http = std::make_unique<HttpClient>(*m_sslContext, host, port);
}

/* ===== helper to build HttpRequest ===== */
HttpRequest Client::buildRequest(const QString& ep,
                                 const QString& method,
                                 const QJsonObject& payload)
{
    HttpRequest req;
    req.method = method.toStdString();
    req.path   = ep.toStdString();

    QUrl u(m_baseUrl);
    req.headers["Host"]        = u.host().toStdString();
    req.headers["User-Agent"]  = "ChrisPlusPlus/1.0";
    req.headers["Content-Type"]= "application/json";
    if (!m_apiKey.isEmpty())
        req.headers["Authorization"] =
            ("Bearer " + m_apiKey).toStdString();

    if (method.compare("POST",Qt::CaseInsensitive)==0 ||
        method.compare("PUT", Qt::CaseInsensitive)==0)
    {
        QJsonDocument d(payload);
        req.body = d.toJson(QJsonDocument::Compact).toStdString();
    }
    return req;
}

/* ===== blocking ===== */
void Client::sendRequest(const QString& ep,
                         const QString& method,
                         const QJsonObject& data)
{
    try {
        HttpRequest  r  = buildRequest(ep, method, data);
        HttpResponse resp = m_http->sendRequest(r);

        QJsonObject obj =
            QJsonDocument::fromJson(QByteArray::fromStdString(resp.body)).object();
        obj["endpoint"] = ep;
        emit responseReceived(resp.statusCode, obj);
    } catch (const std::exception& ex) {
        emit networkError(QString::fromUtf8(ex.what()));
    }
}

/* ===== async wrapper ===== */
void Client::sendAsync(const QString& ep,const QString& method,const QJsonObject& data,
                       std::function<void(int,const QJsonObject&)> ok,
                       std::function<void(const QString&)>         err)
{
    HttpRequest r = buildRequest(ep, method, data);
    m_http->sendAsync(r,
        [ok,ep](const HttpResponse& resp){
            QJsonObject obj =
                QJsonDocument::fromJson(QByteArray::fromStdString(resp.body)).object();
            obj["endpoint"] = ep;
            ok(resp.statusCode, obj);
        },
        std::move(err));
}
