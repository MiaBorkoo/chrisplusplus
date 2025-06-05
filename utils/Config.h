//Config.h
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

    // Server configuration constants
    static constexpr const char* DEFAULT_HOST = "chrisplusplus.gobbler.info";
    static constexpr const char* DEFAULT_PORT = "443";
    static constexpr const char* DEFAULT_URL = "https://chrisplusplus.gobbler.info";
    static constexpr const char* DEFAULT_HTTPS_PORT = "443";
    static constexpr const char* DEFAULT_HTTP_PORT = "80";
    static constexpr const char* PRODUCTION_HOST = "chrisplusplus.gobbler.info";
    static constexpr const char* PRODUCTION_PORT = "443";
    static constexpr const char* PRODUCTION_URL = "https://chrisplusplus.gobbler.info";

    // Client configuration
    static constexpr const char* USER_AGENT = "ChrisPlusPlus-Files/1.0";
    static constexpr int DEFAULT_TIMEOUT_SECONDS = 30;
    static constexpr int UPLOAD_TIMEOUT_SECONDS = 60;
    static constexpr int DOWNLOAD_TIMEOUT_SECONDS = 60;

    // API endpoints
    static constexpr const char* FILES_BASE = "/api/files";
    static constexpr const char* FILES_UPLOAD = "/api/files/upload";
    static constexpr const char* FILES_DOWNLOAD = "/api/files/{file_id}/download";
    static constexpr const char* FILES_METADATA = "/api/files/{file_id}/metadata";
    static constexpr const char* FILES_LIST = "/api/files";
    static constexpr const char* FILES_DELETE = "/api/files/delete";
    static constexpr const char* FILES_SHARE = "/api/files/share";
    static constexpr const char* FILES_SHARES_RECEIVED = "/api/files/shares/received";

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