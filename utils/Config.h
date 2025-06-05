// utils/Config.h
#pragma once

#include <QString>
#include <QSettings>
#include <memory>

class Config {
public:
    static Config& getInstance();

    QString getServerUrl() const;
    QString getServerHost() const;
    QString getServerPort() const;

    void setServerUrl(const QString& url);
    void setServerHost(const QString& host);
    void setServerPort(const QString& port);

    void loadConfig();
    void saveConfig();
    void reset();
    void setProductionMode(bool enable);

    static constexpr const char* DEFAULT_HOST = "localhost";
    static constexpr const char* DEFAULT_PORT = "8000";
    static constexpr const char* DEFAULT_URL = "http://localhost:8000";
    static constexpr const char* DEFAULT_HTTPS_PORT = "443";
    static constexpr const char* DEFAULT_HTTP_PORT = "80";
    static constexpr const char* PRODUCTION_HOST = "api.chrisplusplus.com";
    static constexpr const char* PRODUCTION_PORT = "443";
    static constexpr const char* PRODUCTION_URL = "https://api.chrisplusplus.com";

private:
    Config();
    ~Config() = default;

    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    void setDefaults();

    QString m_serverUrl;
    QString m_serverHost;
    QString m_serverPort;
    std::unique_ptr<QSettings> m_settings;
};