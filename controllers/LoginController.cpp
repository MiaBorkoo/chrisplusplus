#include "LoginController.h"
#include <QMessageBox>

LoginController::LoginController(QObject *parent) : QObject(parent), m_view(nullptr){}

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

    //clears the fields
    m_view->clearFields();

    // Show success message
    QMessageBox::information(nullptr, "Login", "Logged in successfully!");
} 