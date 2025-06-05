#include "LoginController.h"
#include <QMessageBox>

LoginController::LoginController(std::shared_ptr<LoginModel> model, QObject *parent) 
    : QObject(parent), m_view(nullptr), m_model(model)
{
    // Connect model signals
    connect(m_model.get(), &LoginModel::loginSuccess,
            this, &LoginController::handleLoginSuccess);
    connect(m_model.get(), &LoginModel::loginError,
            this, &LoginController::handleLoginError);
}

void LoginController::setView(LoginView *view)
{
    m_view = view;
    if (m_view) {
        connect(m_view, &LoginView::loginAttempted,
                this, &LoginController::handleLoginAttempt);
    }
}

void LoginController::handleLoginAttempt()
{
    if (!m_view) return;

    QString username = m_view->getUsername();
    QString password = m_view->getPassword();

    if (username.isEmpty() || password.isEmpty()) {
        m_view->showError("Please enter both username and password");
        return;
    }

    // Forward login request to model
    m_model->login(username, password);
}

void LoginController::handleLoginSuccess()
{
    if (m_view) {
        m_view->clearFields();
    }
    emit loginSuccessful();
}

void LoginController::handleLoginError(const QString& error)
{
    if (m_view) {
        m_view->showError(error);
    }
} 