#include "LoginController.h"
#include "TOTPController.h"
#include <QMessageBox>
#include <QDebug>

LoginController::LoginController(QObject *parent) 
    : QObject(parent), m_view(nullptr)
{
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
    
    // Initialize models with AuthService
    m_model = std::make_unique<LoginModel>(authService, this);
    m_totpModel = std::make_unique<TOTPModel>(authService, this);
    
    // Initialize TOTP controller
    m_totpController = std::make_unique<TOTPController>(this);
    m_totpController->setModel(m_totpModel.get());
    
    // Connect model signals
    connect(m_model.get(), &LoginModel::loginSuccess,
            this, &LoginController::handleLoginSuccess);
    connect(m_model.get(), &LoginModel::loginError,
            this, &LoginController::handleLoginError);
    
    // Connect TOTP model signals
    connect(m_totpModel.get(), &TOTPModel::setupRequired,
            m_totpController.get(), &TOTPController::showSetupDialog);
    connect(m_totpModel.get(), &TOTPModel::codeRequired,
            m_totpController.get(), &TOTPController::showCodeDialog);
    connect(m_totpModel.get(), &TOTPModel::verificationSuccess,
            this, &LoginController::handleLoginSuccess);
}

void LoginController::handleLoginAttempt()
{
    if (!m_view) {
        qDebug() << "No view set for LoginController";
        return;
    }
    
    if (!m_model) {
        qDebug() << "No model set for LoginController - call setAuthService() first";
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

    qDebug() << "Starting login process for user:" << username;
    
    // Use the model to perform login
    m_model->login(username, password);
}

void LoginController::handleLoginSuccess()
{
    qDebug() << "Login successful - switching to main dashboard";
    
    if (m_view) {
        m_view->clearFields();
    }
    
    emit loginSuccessful();
}

void LoginController::handleLoginError(const QString &error)
{
    qDebug() << "Login error:" << error;
    
    if (m_view) {
        m_view->showError(error);
    }
} 