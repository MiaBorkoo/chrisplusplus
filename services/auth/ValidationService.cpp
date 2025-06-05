#include "ValidationService.h"
#include <QRegularExpression>

ValidationService::ValidationService() {
    // Initialize common passwords
    m_commonPasswords = QSet<QString>({
        "123456789012", "password1234", "qwertyuiop12",
        "iloveyou1234", "adminadmin12", "letmeinplease",
        "footballrules", "welcome12345", "monkeymonkey",
        "sunshine2020", "superman1234", "dragonfire12",
        "trustno1ever", "baseball1234", "ilovefootball",
        "password12345", "abc123abc123", "mysecurelogin"
    });
}

bool ValidationService::validateUsername(const QString& username, QString& errorMessage) const {
    if (username.length() < 3) {
        errorMessage = "Username must be at least 3 characters long";
        return false;
    }
    
    QRegularExpression regex("^[a-zA-Z0-9_-]+$");
    if (!regex.match(username).hasMatch()) {
        errorMessage = "Username can only contain letters, numbers, underscores and hyphens";
        return false;
    }
    
    return true;
}

bool ValidationService::validatePassword(const QString& password, QString& errorMessage) const {
    if (password.length() < 8) {
        errorMessage = "Password must be at least 8 characters long";
        return false;
    }
    
    QRegularExpression hasUpper("[A-Z]");
    QRegularExpression hasLower("[a-z]");
    QRegularExpression hasNumber("[0-9]");
    QRegularExpression hasSpecial("[!@#$%^&*(),.?\":{}|<>]");
    
    if (!hasUpper.match(password).hasMatch()) {
        errorMessage = "Password must contain at least one uppercase letter";
        return false;
    }
    
    if (!hasLower.match(password).hasMatch()) {
        errorMessage = "Password must contain at least one lowercase letter";
        return false;
    }
    
    if (!hasNumber.match(password).hasMatch()) {
        errorMessage = "Password must contain at least one number";
        return false;
    }
    
    if (!hasSpecial.match(password).hasMatch()) {
        errorMessage = "Password must contain at least one special character";
        return false;
    }
    
    if (isCommonPassword(password)) {
        errorMessage = "This password is too common. Please choose a more unique password";
        return false;
    }
    
    return true;
}

bool ValidationService::validatePasswordMatch(const QString& password, const QString& confirmPassword, QString& errorMessage) const {
    if (password != confirmPassword) {
        errorMessage = "Passwords do not match";
        return false;
    }
    return true;
}

bool ValidationService::isCommonPassword(const QString& password) const {
    // This is a very basic implementation. In a real application,
    // you would want to check against a proper list of common passwords
    static const QStringList commonPasswords = {
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "password1", "abc123", "football"
    };
    
    return commonPasswords.contains(password.toLower());
} 