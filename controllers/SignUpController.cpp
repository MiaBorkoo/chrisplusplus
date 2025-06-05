#include "SignUpController.h"
#include <QRegularExpression>
#include <QDebug>

SignUpController::SignUpController(SignUpView *view, std::shared_ptr<SignUpModel> model, QObject *parent) 
    : QObject(parent), view(view), m_model(model)
{
    commonPasswords = QSet<QString>({
        "123456789012", "password1234", "qwertyuiop12",
        "iloveyou1234", "adminadmin12", "letmeinplease",
        "footballrules", "welcome12345", "monkeymonkey",
        "sunshine2020", "superman1234", "dragonfire12",
        "trustno1ever", "baseball1234", "ilovefootball",
        "password12345", "abc123abc123", "mysecurelogin"
    });

    // Connect view signals
    connect(view, &SignUpView::signUpRequested, this, &SignUpController::onSignUpClicked);
    
    // Connect model signals  
    connect(m_model.get(), &SignUpModel::registrationSuccess,
            this, &SignUpController::registrationSuccessful);
    connect(m_model.get(), &SignUpModel::registrationError,
            this, [this](const QString& error) {
                this->view->showError(error);
                emit registrationFailed(error);
            });
}

void SignUpController::onSignUpClicked(const QString &username, const QString &password, const QString &confirmPassword) {
    view->hideError();

    // Validate username
    QString usernameError;
    if (!isUsernameValid(username, usernameError)) {
        view->showError(usernameError);
        return;
    }

    // Validate password
    QString passwordError;
    if (!isPasswordValid(password, passwordError)) {
        view->showError(passwordError);
        return;
    }

    if (password != confirmPassword) {
        view->showError("Passwords do not match.");
        return;
    }

    // Check if password contains username
    if (password.toLower().contains(username.toLower())) {
        view->showError("Password cannot contain your username.");
        return;
    }

    // Actually perform registration instead of fake success
    if (m_model) {
        view->clearFields();
        view->showError("Registering user..."); // Show loading message
        m_model->registerUser(username, password, confirmPassword);
    } else {
        view->showError("Registration service not available.");
    }
}

bool SignUpController::isUsernameValid(const QString &username, QString &errorMessage) {
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

bool SignUpController::isPasswordValid(const QString &password, QString &errorMessage) {
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

bool SignUpController::isCommonPassword(const QString &password) const {
    return commonPasswords.contains(password) || 
           commonPasswords.contains(password.toLower());
}

