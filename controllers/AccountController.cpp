#include "AccountController.h"
#include "../views/HeaderWidget.h"
#include "../views/AccountSection.h"
#include <QPoint>

AccountController::AccountController(HeaderWidget* headerWidget, AccountSection* accountSection, QObject* parent)
    : QObject(parent), m_headerWidget(headerWidget), m_accountSection(accountSection) 
{
    connect(m_headerWidget->accountButton(), &QPushButton::clicked,
            this, &AccountController::onAccountButtonClicked);

    connect(m_accountSection, &AccountSection::changePasswordRequested,
            this, &AccountController::onChangePasswordRequested);
}

void AccountController::onAccountButtonClicked() {
    if (m_accountSection->isVisible()) {
        m_accountSection->hide();
    } else {
        // Set the username every time before showing
        m_accountSection->setUsername(m_currentUsername);

        //gets bottom-right of account button in global coordinates
        QPoint buttonBottomRight = m_headerWidget->accountButton()->mapToGlobal(
            QPoint(m_headerWidget->accountButton()->width(), m_headerWidget->accountButton()->height())
        );

        // Adjust so the AccountSection's top-right aligns with that point
        int x = buttonBottomRight.x() - m_accountSection->width();
        int y = buttonBottomRight.y();

        m_accountSection->move(x, y);
        m_accountSection->show();
        m_accountSection->raise();
        m_accountSection->activateWindow();
    }
}

void AccountController::onChangePasswordRequested(const QString& oldPass, const QString& newPass) {
    // Here, handle password change logic - call model, validate, etc.
    // For demo, just print to console or show a message box:
    // TODO: Replace with actual business logic

    if (oldPass.isEmpty() || newPass.isEmpty()) {
        // You can add signals to AccountSection for errors or use a messagebox
        return;
    }

    // Example: just print to console for now
    qDebug("Password change requested: old = %s, new = %s", oldPass.toUtf8().constData(), newPass.toUtf8().constData());

    // On success, maybe hide the account section or show success message
    m_accountSection->hide();
}