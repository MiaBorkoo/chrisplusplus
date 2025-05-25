#ifndef LOGINVIEW_H
#define LOGINVIEW_H

#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;

class LoginView : public QWidget
{
    Q_OBJECT

public:
    explicit LoginView(QWidget *parent = nullptr);
    QString getUsername() const;
    QString getPassword() const;
    void showError(const QString &message);
    void clearFields();

signals:
    void loginAttempted(const QString &username, const QString &password);
    void signUpClicked();

private slots:
    void handleLogin();
    void handleSignUp();

private:
    QLabel *usernameLabel;
    QLabel *passwordLabel;
    QLineEdit *usernameEdit;
    QLineEdit *passwordEdit;
    QPushButton *loginButton;
    QPushButton *signUpButton;
};

#endif // LOGINVIEW_H