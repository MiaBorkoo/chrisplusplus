#include "AccessController.h"
#include <QDebug>
#include <QMessageBox>

AccessController::AccessController(const QString &fileName, std::shared_ptr<AccessModel> model, QObject *parent)
    : QObject(parent), m_fileName(fileName), m_dialog(nullptr), m_model(model)
{
    // Connect model signals
    connect(m_model.get(), &AccessModel::accessGranted,
            this, &AccessController::handleAccessGranted);
    connect(m_model.get(), &AccessModel::accessRevoked,
            this, &AccessController::handleAccessRevoked);
    connect(m_model.get(), &AccessModel::usersWithAccessReceived,
            this, &AccessController::handleUsersReceived);
    connect(m_model.get(), &AccessModel::errorOccurred,
            this, &AccessController::handleError);

    // Get initial list of users with access
    m_model->getUsersWithAccess(fileName);
}

void AccessController::setView(AccessDialog *dialog) {
    m_dialog = dialog;
    connect(m_dialog, &AccessDialog::addUserRequested, this, &AccessController::handleAddUser);
    connect(m_dialog, &AccessDialog::revokeAccessRequested, this, &AccessController::handleRevokeAccess);
    if (!m_users.isEmpty()) {
        m_dialog->updateUserList(m_users);
    }
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
        m_model->grantAccess(fileName, userName);
    } else {
        QMessageBox::information(m_dialog, "Already Exists", "User already has access.");
    }
}

void AccessController::handleRevokeAccess(const QString &fileName, const QString &userEmail) {
    m_model->revokeAccess(fileName, userEmail);
}

void AccessController::handleAccessGranted(bool success, const QString &fileName, const QString &username) {
    if (success) {
        if (!m_users.contains(username, Qt::CaseInsensitive)) {
            m_users.append(username);
            if (m_dialog) m_dialog->updateUserList(m_users);
        }
    } else {
        QMessageBox::warning(m_dialog, "Error", "Failed to grant access to " + username);
    }
}

void AccessController::handleAccessRevoked(bool success, const QString &fileName, const QString &username) {
    if (success) {
        m_users.removeAll(username);
        if (m_dialog) m_dialog->updateUserList(m_users);
    } else {
        QMessageBox::warning(m_dialog, "Error", "Failed to revoke access from " + username);
    }
}

void AccessController::handleUsersReceived(const QString &fileName, const QStringList &users) {
    m_users = users;
    if (m_dialog) m_dialog->updateUserList(m_users);
}

void AccessController::handleError(const QString &error) {
    QMessageBox::warning(m_dialog, "Error", error);
}
