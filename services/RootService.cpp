#include "RootService.h"

RootService::RootService(std::shared_ptr<Client> client, QObject* parent)
    : ApiService(parent), m_client(client)
{
    if (m_client) {
        connect(m_client.get(), SIGNAL(responseReceived(int, QJsonObject)),
                this, SLOT(handleResponseReceived(int, QJsonObject)));
        connect(m_client.get(), SIGNAL(networkError(QString)),
                this, SLOT(handleNetworkError(QString)));
    }
}

void RootService::getRoot() {
    if (!m_client) {
        emit errorOccurred("RootService not properly initialized");
        return;
    }

    QJsonObject payload;  // Empty payload for root endpoint
    m_client->sendRequest("/", "GET", payload);
}

void RootService::handleResponseReceived(int status, const QJsonObject& data) {
    QString endpoint = data.value("endpoint").toString();
    
    if (endpoint == "/") {
        emit rootResponse(data);
    }
}

void RootService::handleNetworkError(const QString& error) {
    reportError(error);
} 