#include "AccessController.h"
#include <QDebug>
#include <QMessageBox>

AccessController::AccessController(const QString &fileName, const QStringList &users, QObject *parent)
    : QObject(parent), m_fileName(fileName), m_users(users), m_dialog(nullptr)
{
}

void AccessController::setView(AccessDialog *dialog) {
    m_dialog = dialog;
    connect(m_dialog, &AccessDialog::addUserRequested, this, &AccessController::handleAddUser);
    connect(m_dialog, &AccessDialog::revokeAccessRequested, this, &AccessController::handleRevokeAccess);
    m_dialog->updateUserList(m_users);
}

QStringList AccessController::getUsers() const {
    return m_users;
}

void AccessController::handleAddUser(const QString &fileName, const QString &userName) {
    if (userName.isEmpty()) {
        QMessageBox::warning(m_dialog, "Input Error", "Please enter a username.");
        return;
    }
    if (!m_users.contains(userName, Qt::CaseInsensitive)) {
        m_users.append(userName);
        if (m_dialog) m_dialog->updateUserList(m_users);
    } else {
        QMessageBox::information(m_dialog, "Already Exists", "User already has access.");
    }
}

void AccessController::handleRevokeAccess(const QString &fileName, const QString &userEmail) {
    m_users.removeAll(userEmail);
    if (m_dialog) m_dialog->updateUserList(m_users);
}
