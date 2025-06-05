#include "Config.h"
#include <QUrl>
#include <QDir>

void Config::loadConfig() {
    // Load values from settings, use defaults if not found
    m_serverUrl = m_settings->value("server/url", m_serverUrl).toString();
    m_serverHost = m_settings->value("server/host", m_serverHost).toString();
    m_serverPort = m_settings->value("server/port", m_serverPort).toString();
    
    // Validate URL format
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

void Config::setDefaults() {
    m_serverUrl = "https://chrisplusplus.gobbler.info/";
    m_serverHost = "chrisplusplus";
    m_serverPort = "443";
} 