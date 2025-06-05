#pragma once
#include <QString>
#include <QSet>

class ValidationService {
public:
    ValidationService();
    
    // Username validation
    bool validateUsername(const QString& username, QString& errorMessage) const;
    
    // Password validation
    bool validatePassword(const QString& password, const QString& username, QString& errorMessage) const;
    bool validatePasswordMatch(const QString& password, const QString& confirmPassword, QString& errorMessage) const;
    bool isCommonPassword(const QString& password) const;

private:
    QSet<QString> m_commonPasswords;
    
    // Constants
    const int MIN_USERNAME_LENGTH = 3;
    const int MAX_USERNAME_LENGTH = 50;
    const int MIN_PASSWORD_LENGTH = 12;
    const int MAX_PASSWORD_LENGTH = 128;
}; 