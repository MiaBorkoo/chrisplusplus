#include "SignUpView.h"
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QFont>
#include <QPixmap>
#include <QRegularExpression>
#include <QPainter>
#include <QLinearGradient>
#include <QColor>

SignUpView::SignUpView(QWidget *parent) : QWidget(parent)
{
    commonPasswords = QSet<QString>({
    "123456789012",
    "password1234",
    "qwertyuiop12",
    "iloveyou1234",
    "adminadmin12",
    "letmeinplease",
    "footballrules",
    "welcome12345",
    "monkeymonkey",
    "sunshine2020",
    "superman1234",
    "dragonfire12",
    "trustno1ever",
    "baseball1234",
    "ilovefootball",
    "password12345",
    "abc123abc123",
    "mysecurelogin"
    });

    QFont headingFont("Helvetica Neue", 32, QFont::Bold);
    QFont labelFont("Arial", 12, QFont::Bold);
    QFont inputFont("Arial", 11);
    QFont buttonFont("Arial", 11, QFont::Bold);

   
    logoLabel = new QLabel;
    logoLabel->setPixmap(QPixmap(":/assets/logo.png").scaled(100, 100, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    logoLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    logoLabel->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);


    QLabel *headingLabel = new QLabel("Sign Up for an Account");
    headingLabel->setFont(headingFont);
    headingLabel->setStyleSheet("color: white;");
    headingLabel->setAlignment(Qt::AlignCenter);

    QString inputStyle = "QLineEdit { background: white; color: black; border-radius: 20px; border: 2px solid #d4d4d4; font-size: 11px; }";

    // Username
    usernameLabel = new QLabel("Username:");
    usernameLabel->setFont(labelFont);
    usernameLabel->setStyleSheet("color: white;");
    usernameEdit = new QLineEdit;
    usernameEdit->setFont(inputFont);
    usernameEdit->setFixedSize(250, 40);
    usernameEdit->setAlignment(Qt::AlignCenter);
    usernameEdit->setPlaceholderText("Enter username");
    usernameEdit->setStyleSheet(inputStyle);

    // Password
    passwordLabel = new QLabel("Password:");
    passwordLabel->setFont(labelFont);
    passwordLabel->setStyleSheet("color: white;");
    passwordEdit = new QLineEdit;
    passwordEdit->setFont(inputFont);
    passwordEdit->setFixedSize(250, 40);
    passwordEdit->setAlignment(Qt::AlignCenter);
    passwordEdit->setPlaceholderText("Enter password");
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordEdit->setStyleSheet(inputStyle);

    // Confirm Password
    confirmPasswordLabel = new QLabel("Confirm Password:");
    confirmPasswordLabel->setFont(labelFont);
    confirmPasswordLabel->setStyleSheet("color: white;");
    confirmPasswordEdit = new QLineEdit;
    confirmPasswordEdit->setFont(inputFont);
    confirmPasswordEdit->setFixedSize(250, 40);
    confirmPasswordEdit->setAlignment(Qt::AlignCenter);
    confirmPasswordEdit->setPlaceholderText("Re-enter password");
    confirmPasswordEdit->setEchoMode(QLineEdit::Password);
    confirmPasswordEdit->setStyleSheet(inputStyle);

    // Error label
    errorLabel = new QLabel;
    errorLabel->setStyleSheet("color: #ff4444; font-size: 11px;");
    errorLabel->setAlignment(Qt::AlignCenter);
    errorLabel->hide();

    // Sign-Up button
    signUpButton = new QPushButton("Sign Up");
    signUpButton->setFont(buttonFont);
    signUpButton->setFixedSize(250, 40);
    signUpButton->setStyleSheet("QPushButton { background: #00e5e0; color: black; border-radius: 20px; border: none; padding: 10px; font-size: 14px; } QPushButton:hover { background: #00ccc6; }");
    connect(signUpButton, &QPushButton::clicked, this, &SignUpView::handleSignUp);

    //to go back to login page
    QLabel *loginText = new QLabel("Already have an account? <a href=\"#\"><span style='text-decoration: underline; color: #00e5e0;'>Login</span></a>");
    loginText->setTextFormat(Qt::RichText); //tells qt to treat the text as rich text
    loginText->setTextInteractionFlags(Qt::TextBrowserInteraction); //allows the text to be clicked
    loginText->setOpenExternalLinks(false); //prevents the text from being clicked to open a link in an external broswer, i.e we handle it ourselves
    loginText->setAlignment(Qt::AlignCenter);
    loginText->setStyleSheet("color: white; font-size: 12px;");
    connect(loginText, &QLabel::linkActivated, this, [this](const QString &){ emit loginRequested(); });
    //connects the loginText label to the loginRequested signal, [this] captures the current object to emit the signal


    // Form layout
    QVBoxLayout *formLayout = new QVBoxLayout;
    formLayout->setAlignment(Qt::AlignCenter);
    formLayout->setSpacing(3);  
    formLayout->addWidget(headingLabel);

    // Username
    formLayout->addSpacing(20);  
    formLayout->addWidget(usernameLabel, 0, Qt::AlignCenter);
    formLayout->addWidget(usernameEdit, 0, Qt::AlignCenter);

    // Password
    formLayout->addSpacing(15);  
    formLayout->addWidget(passwordLabel, 0, Qt::AlignCenter);
    formLayout->addWidget(passwordEdit, 0, Qt::AlignCenter);

    // Confirm Password
    formLayout->addSpacing(15);  
    formLayout->addWidget(confirmPasswordLabel, 0, Qt::AlignCenter);
    formLayout->addWidget(confirmPasswordEdit, 0, Qt::AlignCenter);

    // Error and Sign Up
    formLayout->addSpacing(10);
    formLayout->addWidget(errorLabel, 0, Qt::AlignCenter);
    formLayout->addWidget(signUpButton, 0, Qt::AlignCenter);
    formLayout->addSpacing(10);
    formLayout->addWidget(loginText, 0, Qt::AlignCenter);

    QWidget *formBox = new QWidget;
    formBox->setLayout(formLayout);
    formBox->setStyleSheet("background: #111; padding: 32px;");
    formBox->setObjectName("signUpPanel");

    //Main layout of the sign-up page
    QVBoxLayout *mainLayout = new QVBoxLayout;
    mainLayout->addWidget(logoLabel, 0, Qt::AlignLeft | Qt::AlignTop);
    mainLayout->addStretch();
    mainLayout->addWidget(formBox, 0, Qt::AlignHCenter);
    mainLayout->addStretch();

    setLayout(mainLayout);
    setAttribute(Qt::WA_StyledBackground, true);
}

QString SignUpView::getUsername() const { return usernameEdit->text(); }
QString SignUpView::getPassword() const { return passwordEdit->text(); }
QString SignUpView::getConfirmPassword() const { return confirmPasswordEdit->text(); }

void SignUpView::showError(const QString &message) {
    errorLabel->setText(message);
    errorLabel->show();
}

void SignUpView::clearFields() {
    usernameEdit->clear();
    passwordEdit->clear();
    confirmPasswordEdit->clear();
    errorLabel->hide();
}

bool SignUpView::isPasswordValid(const QString &password) {
    if (password.length() < 12)
        return false;
    if (!password.contains(QRegularExpression("[A-Za-z]")))
        return false;
    if (!password.contains(QRegularExpression("[0-9]")))
        return false;
    if (commonPasswords.contains(password))
        return false;
    return true;
}

void SignUpView::handleSignUp() {
    QString username = getUsername();
    QString password = getPassword();
    QString confirmPassword = getConfirmPassword();
    errorLabel->hide();

    if (username.isEmpty() || password.isEmpty() || confirmPassword.isEmpty()) {
        showError("All fields are required.");
        return;
    }
    if (password != confirmPassword) {
        showError("Passwords do not match.");
        return;
    }
    if (!isPasswordValid(password)) {
        showError("Password must be at least 12 characters, contain letters and numbers, and not be a common password.");
        return;
    }
    clearFields();
    showError("Sign up successful!");
}

void SignUpView::handleLogin() {
    emit loginRequested();
}

void SignUpView::paintEvent(QPaintEvent *event) {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    QLinearGradient gradient(0, 0, width(), height());
    gradient.setColorAt(0, QColor("#222222"));
    gradient.setColorAt(1, QColor("#23a6d5"));
    painter.fillRect(rect(), gradient);
    QWidget::paintEvent(event);
}