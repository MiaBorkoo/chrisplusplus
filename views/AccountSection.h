#ifndef ACCOUNTSECTION_H
#define ACCOUNTSECTION_H

#include <QWidget>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>

class AccountSection : public QWidget {
    Q_OBJECT
public:
    explicit AccountSection(QWidget *parent = nullptr);
    void setUsername(const QString& username);
    void clearFields();
    void showErrorMessage(const QString& message);

signals:
    void changePasswordRequested(const QString& oldPass, const QString& newPass);

private:
    QLabel* m_usernameLabel;
    QLineEdit* m_oldPassword;
    QLineEdit* m_newPassword;
    QLineEdit* m_confirmPassword;
    QPushButton* m_changePasswordBtn;
    QLabel* m_successLabel;
    QLabel* m_errorLabel;

private slots:
    void onChangePasswordClicked();

};

#endif // ACCOUNTSECTION_H