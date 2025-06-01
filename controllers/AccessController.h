#ifndef ACCESSCONTROLLER_H
#define ACCESSCONTROLLER_H

#include <QObject>
#include <QStringList>
#include "../views/AccessDialog.h"

class AccessController : public QObject {
    Q_OBJECT
public:
    AccessController(const QString &fileName, const QStringList &users, QObject *parent = nullptr);
    void setView(AccessDialog *dialog);
    QStringList getUsers() const;

private slots:
    void handleAddUser(const QString &fileName, const QString &userEmail);
    void handleRevokeAccess(const QString &fileName, const QString &userEmail);

private:
    QString m_fileName;
    QStringList m_users;
    AccessDialog *m_dialog;
};

#endif // ACCESSCONTROLLER_H
