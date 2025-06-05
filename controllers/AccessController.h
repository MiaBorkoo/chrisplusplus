#ifndef ACCESSCONTROLLER_H
#define ACCESSCONTROLLER_H

#include <QObject>
#include <QStringList>
#include "../views/AccessDialog.h"
#include "../models/AccessModel.h"
#include <memory>

class AccessController : public QObject {
    Q_OBJECT
public:
    explicit AccessController(const QString &fileName, std::shared_ptr<AccessModel> model, QObject *parent = nullptr);
    void setView(AccessDialog *dialog);
    QStringList getUsers() const;

private slots:
    void handleAddUser(const QString &fileName, const QString &userEmail);
    void handleRevokeAccess(const QString &fileName, const QString &userEmail);
    void handleAccessGranted(bool success, const QString &fileName, const QString &username);
    void handleAccessRevoked(bool success, const QString &fileName, const QString &username);
    void handleUsersReceived(const QString &fileName, const QStringList &users);
    void handleError(const QString &error);

private:
    QString m_fileName;
    QStringList m_users;
    AccessDialog *m_dialog;
    std::shared_ptr<AccessModel> m_model;
};

#endif // ACCESSCONTROLLER_H
