#include "SignUpController.h"
#include <QRegularExpression>
#include <QDebug>

SignUpController::SignUpController(SignUpView *view, QObject *parent): QObject(parent), view(view)
{
    commonPasswords = QSet<QString>({
        "123456789012", "password1234", "qwertyuiop12",
        "iloveyou1234", "adminadmin12", "letmeinplease",
        "footballrules", "welcome12345", "monkeymonkey",
        "sunshine2020", "superman1234", "dragonfire12",
        "trustno1ever", "baseball1234", "ilovefootball",
        "password12345", "abc123abc123", "mysecurelogin"
    });

    connect(view, &SignUpView::signUpRequested, this, &SignUpController::onSignUpClicked);

}

void SignUpController::onSignUpClicked(const QString &username, const QString &password, const QString &confirmPassword) {
    view->hideError();

    if (username.isEmpty()) {
        view->showError("Username is required.");
        return;
    }
    if (password.isEmpty()) {
        view->showError("Password is required.");
        return;
    }
    if (confirmPassword.isEmpty()) {
        view->showError("Please confirm your password.");
        return;
    }

    if (password != confirmPassword) {
        view->showError("Passwords do not match.");
        return;
    }

    // Validate password and get specific error message
    QString errorMessage;
    if (!isPasswordValid(password, errorMessage)) {
        view->showError(errorMessage);
        return;
    }
    view->clearFields();
    view->showError("Sign up successful! (debug mode)"); 
}

bool SignUpController::isPasswordValid(const QString &password, QString &errorMessage) {
    if (password.length() < 12) {
        errorMessage = "Password must be at least 12 characters.";
        return false;
    }
    if (!password.contains(QRegularExpression("[A-Za-z]")) || !password.contains(QRegularExpression("[0-9]"))) {
        errorMessage = "Password must contain both letters and numbers.";
        return false;
    }
    if (commonPasswords.contains(password)) {
        errorMessage = "Password is too common. Please choose a less common password.";
        return false;
    }
    return true;
}