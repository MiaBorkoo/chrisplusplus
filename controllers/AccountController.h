#ifndef ACCOUNTCONTROLLER_H
#define ACCOUNTCONTROLLER_H

#include <QObject>

class HeaderWidget;
class AccountSection;

class AccountController : public QObject {
    Q_OBJECT
public:
    AccountController(HeaderWidget* headerWidget, AccountSection* accountSection, QObject* parent = nullptr);

private slots:
    void onAccountButtonClicked();
    void onChangePasswordRequested(const QString& oldPass, const QString& newPass);

private:
    HeaderWidget* m_headerWidget;
    AccountSection* m_accountSection;

    QString m_currentUsername = "User123";  // Example username, could come from model/session
};

#endif // ACCOUNTCONTROLLER_H