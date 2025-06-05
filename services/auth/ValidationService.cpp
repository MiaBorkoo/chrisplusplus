#include "ValidationService.h"
#include <QRegularExpression>

ValidationService::ValidationService() {
    // Initialize common passwords with a more comprehensive list
    m_commonPasswords = QSet<QString>({
        "123456789012", "password1234", "qwertyuiop12",
        "iloveyou1234", "adminadmin12", "letmeinplease",
        "footballrules", "welcome12345", "monkeymonkey",
        "sunshine2020", "superman1234", "dragonfire12",
        "trustno1ever", "baseball1234", "ilovefootball",
        "password12345", "abc123abc123", "mysecurelogin",
        // Add basic common passwords too
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "password1", "abc123", "football"
    });
}

bool ValidationService::validateUsername(const QString& username, QString& errorMessage) const {
    if (username.isEmpty()) {
        errorMessage = "Username is required";
        return false;
    }
    
    if (username.length() < MIN_USERNAME_LENGTH) {
        errorMessage = QString("Username must be at least %1 characters long").arg(MIN_USERNAME_LENGTH);
        return false;
    }
    
    if (username.length() > MAX_USERNAME_LENGTH) {
        errorMessage = QString("Username cannot exceed %1 characters").arg(MAX_USERNAME_LENGTH);
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
    if (password.isEmpty()) {
        errorMessage = "Password is required";
        return false;
    }
    
    if (password.length() < MIN_PASSWORD_LENGTH) {
        errorMessage = QString("Password must be at least %1 characters long").arg(MIN_PASSWORD_LENGTH);
        return false;
    }
    
    if (password.length() > MAX_PASSWORD_LENGTH) {
        errorMessage = QString("Password cannot exceed %1 characters").arg(MAX_PASSWORD_LENGTH);
        return false;
    }
    
    // Check for required character classes
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
    
    // Check for repeating characters
    QRegularExpression repeating("(.)\\1{2,}");
    if (repeating.match(password).hasMatch()) {
        errorMessage = "Password cannot contain repeating characters (e.g., 'aaa')";
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
    return m_commonPasswords.contains(password) || 
           m_commonPasswords.contains(password.toLower());
} 