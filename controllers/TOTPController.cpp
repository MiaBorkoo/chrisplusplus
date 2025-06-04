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
}

void TOTPController::showSetupDialog(const QString &qrCodeBase64)
{
    qDebug() << "TOTPController: Showing setup dialog with QR code";
    
    // Create new dialog each time to ensure it's modal and fresh
    if (m_setupView) {
        m_setupView->deleteLater();
    }
    
    // Find the main window to use as parent
    QWidget *parentWidget = nullptr;
    if (parent()) {
        parentWidget = qobject_cast<QWidget*>(parent());
        if (!parentWidget) {
            // Try to find a widget parent in the hierarchy
            QObject *obj = parent();
            while (obj && !parentWidget) {
                parentWidget = qobject_cast<QWidget*>(obj);
                obj = obj->parent();
            }
        }
    }
    
    m_setupView = new TOTPSetupView(parentWidget);
    m_setupView->setWindowModality(Qt::ApplicationModal);  // Make it modal
    m_setupView->setAttribute(Qt::WA_DeleteOnClose, false); // Don't auto-delete
    
    connect(m_setupView, &TOTPSetupView::verificationCodeEntered,
            this, &TOTPController::handleSetupCode);
    connect(m_setupView, &TOTPSetupView::setupCancelled,
            this, &TOTPController::handleSetupCancelled);
    
    m_setupView->displayQRCode(qrCodeBase64);
    m_setupView->show();
    m_setupView->raise();
    m_setupView->activateWindow();
    
    qDebug() << "TOTPController: Setup dialog should now be visible";
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
    
    if (m_model) {
        m_model->verifySetupCode(code);
    } else {
        qDebug() << "TOTPController: No model set!";
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