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

signals:
    void signUpRequested(const QString &username, const QString &password, const QString &confirmPassword);
    void loginRequested();

private slots:
    void handleSignUp();

private:
    QLabel *logoLabel;
    QLabel *usernameLabel;
    QLabel *passwordLabel;
    QLabel *confirmPasswordLabel;
    QLineEdit *usernameEdit;
    QLineEdit *passwordEdit;
    QLineEdit *confirmPasswordEdit;
    QPushButton *signUpButton;
    QLabel *errorLabel;

    void resetFieldStyles();
    void paintEvent(QPaintEvent *event) override;
};

#endif // SIGNUPVIEW_H
