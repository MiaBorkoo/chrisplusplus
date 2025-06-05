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
    Config() { 
        // Initialize QSettings with organization and application name
        m_settings = std::make_unique<QSettings>("EPIC", "ChrisPlusPlus");
        loadConfig(); 
    }
    ~Config() = default;
    
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    void setDefaults();

    QString m_serverUrl = "https://chrisplusplus.gobbler.info";  // Default value TODO: change to server url
    QString m_serverHost = "chrisplusplus.gobbler.info";
    QString m_serverPort = "443";
    std::unique_ptr<QSettings> m_settings;
}; 