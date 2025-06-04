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
    if (username.isEmpty()) {
        errorMessage = "Username is required.";
        return false;
    }

    if (username.length() < MIN_USERNAME_LENGTH) {
        errorMessage = QString("Username must be at least %1 characters.").arg(MIN_USERNAME_LENGTH);
        return false;
    }

    if (username.length() > MAX_USERNAME_LENGTH) {
        errorMessage = QString("Username cannot exceed %1 characters.").arg(MAX_USERNAME_LENGTH);
        return false;
    }

    // Check for valid characters (alphanumeric and limited special chars)
    QRegularExpression validChars("^[a-zA-Z0-9._-]+$");
    if (!validChars.match(username).hasMatch()) {
        errorMessage = "Username can only contain letters, numbers, dots, underscores, and hyphens.";
        return false;
    }

    return true;
}

bool ValidationService::validatePassword(const QString& password, QString& errorMessage) const {
    if (password.isEmpty()) {
        errorMessage = "Password is required.";
        return false;
    }

    if (password.length() < MIN_PASSWORD_LENGTH) {
        errorMessage = QString("Password must be at least %1 characters.").arg(MIN_PASSWORD_LENGTH);
        return false;
    }

    if (password.length() > MAX_PASSWORD_LENGTH) {
        errorMessage = QString("Password cannot exceed %1 characters.").arg(MAX_PASSWORD_LENGTH);
        return false;
    }

    // Check for letters
    if (!password.contains(QRegularExpression("[A-Za-z]"))) {
        errorMessage = "Password must contain at least one letter.";
        return false;
    }

    // Check for numbers
    if (!password.contains(QRegularExpression("[0-9]"))) {
        errorMessage = "Password must contain at least one number.";
        return false;
    }

    // Check for common passwords
    if (isCommonPassword(password)) {
        errorMessage = "This password is too common. Please choose a stronger password.";
        return false;
    }

    // Check for repeating characters
    QRegularExpression repeating("(.)\\1{2,}");
    if (repeating.match(password).hasMatch()) {
        errorMessage = "Password cannot contain repeating characters (e.g., 'aaa').";
        return false;
    }

    return true;
}

bool ValidationService::validatePasswordMatch(const QString& password, const QString& confirmPassword, QString& errorMessage) const {
    if (password != confirmPassword) {
        errorMessage = "Passwords do not match.";
        return false;
    }
    return true;
}

bool ValidationService::isCommonPassword(const QString& password) const {
    return m_commonPasswords.contains(password) || 
           m_commonPasswords.contains(password.toLower());
} 