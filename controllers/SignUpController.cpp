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

    if (!isPasswordValid(password)) {
        view->showError("Password must be at least 12 characters, contain letters and numbers, and not be a common password.");
        return;
    }

    view->clearFields();
    view->showError("Sign up successful!"); // we will remove this later when it switches to the new page,no message needed
}

bool SignUpController::isPasswordValid(const QString &password) {
    if (password.length() < 12) return false;
    if (!password.contains(QRegularExpression("[A-Za-z]"))) return false;
    if (!password.contains(QRegularExpression("[0-9]"))) return false;
    if (commonPasswords.contains(password)) return false;
    return true;
}