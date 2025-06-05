#ifndef SIGNUPVIEW_H
#define SIGNUPVIEW_H

#include <QWidget>
#include <QString>
#include <QPainter>

class QLabel;
class QLineEdit;
class QPushButton;
class QVBoxLayout;

class SignUpView : public QWidget
{
    Q_OBJECT

public:
    explicit SignUpView(QWidget *parent = nullptr);
    QString getUsername() const;
    QString getPassword() const;
    QString getConfirmPassword() const;
    void showError(const QString &message);
    void clearFields();
    void hideError();
    void handleSignUp();

signals:
    void signUpRequested(const QString &username, const QString &password, const QString &confirmPassword);
    void loginRequested();

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QLabel *logoLabel;
    QLabel *usernameLabel;
    QLabel *passwordLabel;
    QLabel *confirmPasswordLabel;
    QLabel *errorLabel;
    QLineEdit *usernameEdit;
    QLineEdit *passwordEdit;
    QLineEdit *confirmPasswordEdit;
    QPushButton *signUpButton;
    void resetFieldStyles();
};

#endif // SIGNUPVIEW_H
