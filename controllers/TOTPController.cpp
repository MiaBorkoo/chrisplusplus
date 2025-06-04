#include "TOTPController.h"
#include "../views/TOTPSetupView.h"
#include "../views/TOTPCodeDialog.h"
#include "../models/TOTPModel.h"

TOTPController::TOTPController(QObject *parent)
    : QObject(parent), m_model(nullptr), m_setupView(nullptr), m_codeDialog(nullptr)
{
}

void TOTPController::setModel(TOTPModel *model)
{
    m_model = model;
}

void TOTPController::showSetupDialog(const QString &qrCodeBase64)
{
    if (!m_setupView) {
        m_setupView = new TOTPSetupView();
        connect(m_setupView, &TOTPSetupView::verificationCodeEntered,
                this, &TOTPController::handleSetupCode);
        connect(m_setupView, &TOTPSetupView::setupCancelled,
                this, &TOTPController::handleSetupCancelled);
    }
    
    m_setupView->displayQRCode(qrCodeBase64);
    m_setupView->show();
    m_setupView->raise();
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
    emit setupCodeEntered(code);
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