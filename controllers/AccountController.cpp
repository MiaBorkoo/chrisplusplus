#include "AccountController.h"
#include "../views/HeaderWidget.h"
#include "../views/AccountSection.h"
#include <QPoint>
#include <QMessageBox>

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
        // set the username every time before showing
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
    if (oldPass.isEmpty() || newPass.isEmpty()) {
        m_accountSection->showErrorMessage("Fields cannot be empty.");
        m_accountSection->clearFields();
        return;
    }

    // TODO: Replace with actual password change logic, e.g. check old password validity

    bool passwordChangedSuccessfully = true; 

    if (passwordChangedSuccessfully) {
        // Show success popup
        QMessageBox::information(m_accountSection, "Success", "Password changed successfully!");
        m_accountSection->clearFields();
        m_accountSection->hide();  
    } else {
        //On failure, show error label with message
        m_accountSection->showErrorMessage("Failed to change password. Please try again.");
        m_accountSection->clearFields();
    }
}