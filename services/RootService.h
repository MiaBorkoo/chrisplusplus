#pragma once
#include "ApiService.h"
#include "../network/Client.h"
#include <QObject>
#include <QString>
#include <QJsonObject>
#include <memory>

class RootService : public ApiService {
    Q_OBJECT
public:
    explicit RootService(std::shared_ptr<Client> client = nullptr, QObject* parent = nullptr);
    ~RootService() override = default;

    // Root endpoint
    void getRoot();

    bool isInitialized() const override {
        return m_client != nullptr;
    }

signals:
    void rootResponse(const QJsonObject& data);

private slots:
    void handleResponseReceived(int status, const QJsonObject& data);
    void handleNetworkError(const QString& error);

private:
    std::shared_ptr<Client> m_client;
}; 