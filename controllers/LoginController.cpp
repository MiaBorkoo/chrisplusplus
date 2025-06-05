#include "LoginController.h"
#include "TOTPController.h"
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

LoginController::~LoginController()
{
    // Destructor implementation - now TOTPController is a complete type
}

void LoginController::setView(LoginView *view)
{
    m_view = view;
    if (m_view) {
        connect(m_view, &LoginView::loginAttempted,
                this, &LoginController::handleLoginAttempt);
    }
}

void LoginController::setAuthService(std::shared_ptr<AuthService> authService)
{
    m_authService = authService;
    
    // Initialize TOTP model with AuthService
    m_totpModel = std::make_unique<TOTPModel>(authService, this);
    
    // Initialize TOTP controller
    m_totpController = std::make_unique<TOTPController>(this);
    m_totpController->setModel(m_totpModel.get());
    
    // Connect TOTP model signals
    connect(m_totpModel.get(), &TOTPModel::setupRequired,
            m_totpController.get(), &TOTPController::showSetupDialog);
    connect(m_totpModel.get(), &TOTPModel::codeRequired,
            m_totpController.get(), &TOTPController::showCodeDialog);
    connect(m_totpModel.get(), &TOTPModel::verificationSuccess,
            this, &LoginController::handleLoginSuccess);
    
    // Connect TOTP controller signals back to model
    connect(m_totpController.get(), &TOTPController::loginCodeEntered,
            this, &LoginController::handleTOTPCodeEntered);
}

void LoginController::handleLoginAttempt()
{
    if (!m_view) {
        return;
    }
    
    if (!m_model) {
        if (m_view) {
            m_view->showError("Authentication service not initialized");
        }
        return;
    }

    QString username = m_view->getUsername();
    QString password = m_view->getPassword();

    if (username.isEmpty() || password.isEmpty()) {
        m_view->showError("Please enter both username and password");
        return;
    }

    // Store username for use during TOTP flow
    m_currentUsername = username;
    
    // Forward login request to model
    m_model->login(username, password);
}

void LoginController::handleLoginSuccess()
{
    if (m_view) {
        m_view->clearFields();
    }
    
    // Clear stored username
    m_currentUsername.clear();
    
    emit loginSuccessful();
}

void LoginController::handleLoginError(const QString &error)
{
    if (m_view) {
        m_view->showError(error);
    }
}

void LoginController::handleTOTPCodeEntered(const QString &code)
{
    if (!m_totpModel) {
        return;
    }
    
    // TOTPModel handles the username and auth hash internally from stored pending data
    m_totpModel->verifyLoginCode(code, "", "");
} 