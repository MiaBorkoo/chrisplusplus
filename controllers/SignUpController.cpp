#include "SignUpController.h"
#include <QRegularExpression>
#include <QDebug>

SignUpController::SignUpController(SignUpView *view, QObject *parent) 
    : QObject(parent), view(view)
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
}

void SignUpController::setAuthService(std::shared_ptr<AuthService> authService)
{
    m_authService = authService;
    
    // Initialize model with AuthService
    m_model = std::make_unique<SignUpModel>(authService, this);
    
    // Connect model signals
    connect(m_model.get(), &SignUpModel::registrationSuccess,
            this, &SignUpController::handleRegistrationSuccess);
    connect(m_model.get(), &SignUpModel::registrationError,
            this, &SignUpController::handleRegistrationError);
}

void SignUpController::onSignUpClicked(const QString &username, const QString &password, const QString &confirmPassword) {
    view->hideError();

    if (!m_model) {
        qDebug() << "No model set for SignUpController - call setAuthService() first";
        view->showError("Authentication service not initialized");
        return;
    }

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

    qDebug() << "Starting registration process for user:" << username;
    
    // Use the model to perform registration
    m_model->registerUser(username, password, confirmPassword);
}

void SignUpController::handleRegistrationSuccess()
{
    qDebug() << "Registration successful";
    
    if (view) {
        view->clearFields();
        view->showError("Registration successful! You can now log in.");
    }
    
    emit registrationCompleted();
    emit registrationSuccessful(); // For backward compatibility
}

void SignUpController::handleRegistrationError(const QString &error)
{
    qDebug() << "Registration error:" << error;
    
    if (view) {
        view->showError(error);
    }
    
    emit registrationFailed(error); // For backward compatibility
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

