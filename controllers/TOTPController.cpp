#include "TOTPController.h"
#include "../views/TOTPSetupView.h"
#include "../views/TOTPCodeDialog.h"
#include "../models/TOTPModel.h"
#include <QDebug>
#include <QWidget>

TOTPController::TOTPController(QObject *parent)
    : QObject(parent), m_model(nullptr), m_setupView(nullptr), m_codeDialog(nullptr)
{
}

TOTPController::~TOTPController()
{
    // Clean up dialog objects
    if (m_setupView) {
        delete m_setupView;
        m_setupView = nullptr;
    }
    
    if (m_codeDialog) {
        delete m_codeDialog;
        m_codeDialog = nullptr;
    }
}

void TOTPController::setModel(TOTPModel *model)
{
    m_model = model;
    
    if (m_model) {
        // Connect model signals to handle verification results
        connect(m_model, &TOTPModel::verificationSuccess,
                this, &TOTPController::handleVerificationSuccess);
        connect(m_model, &TOTPModel::verificationError,
                this, &TOTPController::handleVerificationError);
        
        qDebug() << "TOTPController: Model set and signals connected";
    }
}

void TOTPController::showSetupDialog(const QString &qrCodeBase64)
{
    qDebug() << "TOTPController: Showing setup dialog with QR code";
    
    // Clean up any existing dialog
    if (m_setupView) {
        qDebug() << "TOTPController: Closing existing setup dialog";
        m_setupView->close();
        delete m_setupView;
        m_setupView = nullptr;
    }
    
    qDebug() << "TOTPController: Creating new setup dialog";
    
    // Create simple dialog without complex parent handling
    m_setupView = new TOTPSetupView();
    m_setupView->setController(this);
    m_setupView->setWindowTitle("Set Up Two-Factor Authentication");
    m_setupView->resize(500, 600);
    
    // Make it a normal window, not modal (for now)
    m_setupView->setWindowFlags(Qt::Window | Qt::WindowStaysOnTopHint);
    
    qDebug() << "TOTPController: Displaying QR code and showing dialog";
    m_setupView->displayQRCode(qrCodeBase64);
    m_setupView->show();
    m_setupView->raise();
    m_setupView->activateWindow();
    
    qDebug() << "TOTPController: Dialog show() called, isVisible:" << m_setupView->isVisible();
}

void TOTPController::showCodeDialog()
{
    if (!m_codeDialog) {
        m_codeDialog = new TOTPCodeDialog();
        m_codeDialog->setController(this);
    }
    
    m_codeDialog->clearCode();
    m_codeDialog->exec();
}

void TOTPController::handleSetupCode(const QString &code)
{
    qDebug() << "TOTPController: Handling setup code:" << code;
    
    if (m_setupView) {
        m_setupView->setSetupInProgress(true);
        m_setupView->clearError();
    }
    
    if (m_model) {
        m_model->verifySetupCode(code);
    } else {
        qDebug() << "TOTPController: No model set!";
        if (m_setupView) {
            m_setupView->showError("Internal error: No TOTP model available");
            m_setupView->setSetupInProgress(false);
        }
    }
}

void TOTPController::handleLoginCode(const QString &code)
{
    emit loginCodeEntered(code);
}

void TOTPController::handleSetupCancelled()
{
    if (m_setupView) {
        m_setupView->close();
    }
    emit setupCancelled();
}

void TOTPController::handleCodeCancelled()
{
    if (m_codeDialog) {
        m_codeDialog->close();
    }
    emit codeCancelled();
}

// Add new slots to handle verification results
void TOTPController::handleVerificationSuccess()
{
    qDebug() << "TOTPController: Verification successful - closing dialogs";
    
    // Close setup dialog if open
    if (m_setupView) {
        m_setupView->close();
        delete m_setupView;
        m_setupView = nullptr;
    }
    
    // Close code dialog if open
    if (m_codeDialog) {
        m_codeDialog->close();
        delete m_codeDialog;
        m_codeDialog = nullptr;
    }
    
    qDebug() << "TOTPController: All dialogs closed after verification success";
}

void TOTPController::handleVerificationError(const QString &error)
{
    qDebug() << "TOTPController: Verification error:" << error;
    
    if (m_setupView) {
        m_setupView->showError(error);
        m_setupView->setSetupInProgress(false);
    }
}

void TOTPController::verifyCode(const QString &code)
{
    // This method handles code verification for both setup and login
    if (m_setupView && m_setupView->isVisible()) {
        // We're in setup mode
        handleSetupCode(code);
    } else {
        // We're in login mode
        handleLoginCode(code);
    }
}

void TOTPController::cancelCodeEntry()
{
    // Handle cancellation based on which dialog is active
    if (m_setupView && m_setupView->isVisible()) {
        handleSetupCancelled();
    } else {
        handleCodeCancelled();
    }
} 