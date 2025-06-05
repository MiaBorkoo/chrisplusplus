// utils/Config.cpp
#include "Config.h"
#include <QUrl>

Config& Config::getInstance() {
    static Config instance;
    return instance;
}

Config::Config() {
    m_settings = std::make_unique<QSettings>("EPIC", "ChrisPlusPlus");
    setDefaults();    // Load hardcoded defaults
    loadConfig();     // Override with saved config
}

void Config::setDefaults() {
    m_serverUrl = "https://chrisplusplus.gobbler.info";
    m_serverHost = "chrisplusplus.gobbler.info";
    m_serverPort = "443";
}

void Config::loadConfig() {
    m_serverUrl = m_settings->value("server/url", m_serverUrl).toString();
    m_serverHost = m_settings->value("server/host", m_serverHost).toString();
    m_serverPort = m_settings->value("server/port", m_serverPort).toString();

    QUrl url(m_serverUrl);
    if (!url.isValid()) {
        setDefaults();
        saveConfig();
    }
}

void Config::saveConfig() {
    m_settings->setValue("server/url", m_serverUrl);
    m_settings->setValue("server/host", m_serverHost);
    m_settings->setValue("server/port", m_serverPort);
    m_settings->sync();
}


void Config::reset() {
    setDefaults();
    saveConfig();
}

void Config::setProductionMode(bool enable) {
    if (enable) {
        m_serverUrl = PRODUCTION_URL;
        m_serverHost = PRODUCTION_HOST;
        m_serverPort = PRODUCTION_PORT;
    } else {
        setDefaults();
    }
    saveConfig();
}

QString Config::getServerUrl() const { return m_serverUrl; }
QString Config::getServerHost() const { return m_serverHost; }
QString Config::getServerPort() const { return m_serverPort; }

void Config::setServerUrl(const QString& url) { m_serverUrl = url; }
void Config::setServerHost(const QString& host) { m_serverHost = host; }
void Config::setServerPort(const QString& port) { m_serverPort = port; }

