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
    m_setupView->setWindowTitle("Set Up Two-Factor Authentication");
    m_setupView->resize(500, 600);
    
    // Make it a normal window, not modal (for now)
    m_setupView->setWindowFlags(Qt::Window | Qt::WindowStaysOnTopHint);
    
    connect(m_setupView, &TOTPSetupView::verificationCodeEntered,
            this, &TOTPController::handleSetupCode);
    connect(m_setupView, &TOTPSetupView::setupCancelled,
            this, &TOTPController::handleSetupCancelled);
    
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
        connect(m_codeDialog, &TOTPCodeDialog::codeEntered,
                this, &TOTPController::handleLoginCode);
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
        m_setupView = nullptr;
    }
    
    // Close code dialog if open
    if (m_codeDialog) {
        m_codeDialog->close();
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