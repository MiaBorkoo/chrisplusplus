#include "SignUpController.h"
#include <QDebug>
#include "../services/auth/ValidationService.h"

SignUpController::SignUpController(SignUpView *view, std::shared_ptr<SignUpModel> model, QObject *parent)
    : QObject(parent), view(view), m_model(model)
{
    connect(view, &SignUpView::signUpRequested, this, &SignUpController::onSignUpClicked);
    
    // Connect model signals
    connect(m_model.get(), &SignUpModel::registrationSuccess, this, &SignUpController::handleRegistrationSuccess);
    connect(m_model.get(), &SignUpModel::registrationError, this, &SignUpController::handleRegistrationError);
}

void SignUpController::onSignUpClicked(const QString &username, const QString &password, const QString &confirmPassword) {
    view->hideError();

    // Validate username
    QString usernameError;
    if (!m_validationService.validateUsername(username, usernameError)) {
        view->showError(usernameError);
        emit m_model->registrationError(usernameError);
        return;
    }

    // Validate password
    QString passwordError;
    if (!m_validationService.validatePassword(password, username, passwordError)) {
        view->showError(passwordError);
        emit m_model->registrationError(passwordError);
        return;
    }

    // Validate password match
    QString matchError;
    if (!m_validationService.validatePasswordMatch(password, confirmPassword, matchError)) {
        view->showError(matchError);
        emit m_model->registrationError(matchError);
        return;
    }

    // Forward registration request to model
    m_model->registerUser(username, password, confirmPassword);
    view->clearFields();  // Clear fields after submitting
}

void SignUpController::handleRegistrationSuccess() {
    view->clearFields();
    emit registrationCompleted();
    emit registrationSuccessful();
}

void SignUpController::handleRegistrationError(const QString &error) {
    view->showError(error);
}
