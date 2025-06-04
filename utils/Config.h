#pragma once

#include <QString>
#include <QSettings>
#include <memory>

class Config {
public:
    static Config& getInstance() {
        static Config instance;
        return instance;
    }

    QString getServerUrl() const { return m_serverUrl; }
    QString getServerHost() const { return m_serverHost; }
    QString getServerPort() const { return m_serverPort; }
    
    void loadConfig();
    void saveConfig();

private:
    Config() { loadConfig(); }  // Constructor is private
    ~Config() = default;
    
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    void setDefaults();

    QString m_serverUrl = "http://localhost:8000";  // Default value
    QString m_serverHost = "localhost";
    QString m_serverPort = "8000";
    std::unique_ptr<QSettings> m_settings;
}; 