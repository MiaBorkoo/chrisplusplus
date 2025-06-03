#include "SignUpView.h"
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QFont>
#include <QPixmap>
#include <QPainter>

SignUpView::SignUpView(QWidget *parent) : QWidget(parent)
{
    QFont headingFont("Helvetica Neue", 28, QFont::DemiBold);
    QFont labelFont("Arial", 14, QFont::Medium);
    QFont inputFont("Arial", 14);
    QFont buttonFont("Arial", 14, QFont::Medium);

    // Logo
    logoLabel = new QLabel;
    logoLabel->setPixmap(QPixmap(":/assets/logo.png").scaled(100, 100, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    logoLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    logoLabel->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

    // Heading
    QLabel *headingLabel = new QLabel("Create Your Account");
    headingLabel->setFont(headingFont);
    headingLabel->setObjectName("signUpHeading");
    headingLabel->setAlignment(Qt::AlignCenter);

    // Username
    usernameLabel = new QLabel("Username:");
    usernameLabel->setFont(labelFont);
    usernameLabel->setObjectName("signUpUsernameLabel");
    usernameEdit = new QLineEdit;
    usernameEdit->setFont(inputFont);
    usernameEdit->setFixedSize(350, 48);
    usernameEdit->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    usernameEdit->setPlaceholderText("Enter username");

    // Password
    passwordLabel = new QLabel("Password:");
    passwordLabel->setFont(labelFont);
    passwordLabel->setObjectName("signUpPasswordLabel");
    passwordEdit = new QLineEdit;
    passwordEdit->setFont(inputFont);
    passwordEdit->setFixedSize(350, 48);
    passwordEdit->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    passwordEdit->setPlaceholderText("Enter password");
    passwordEdit->setEchoMode(QLineEdit::Password);

    // Confirm Password
    confirmPasswordLabel = new QLabel("Confirm Password:");
    confirmPasswordLabel->setFont(labelFont);
    confirmPasswordLabel->setObjectName("signUpConfirmLabel");
    confirmPasswordEdit = new QLineEdit;
    confirmPasswordEdit->setFont(inputFont);
    confirmPasswordEdit->setFixedSize(350, 48);
    confirmPasswordEdit->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    confirmPasswordEdit->setPlaceholderText("Re-enter password");
    confirmPasswordEdit->setEchoMode(QLineEdit::Password);

    // Error label
    errorLabel = new QLabel;
    errorLabel->setObjectName("errorLabel");
    errorLabel->setAlignment(Qt::AlignCenter);
    errorLabel->hide();

    // Sign-Up button
    signUpButton = new QPushButton("Sign Up");
    signUpButton->setFont(buttonFont);
    signUpButton->setFixedSize(350, 48);
    signUpButton->setObjectName("signUpButton");
    connect(signUpButton, &QPushButton::clicked, this, &SignUpView::handleSignUp);

    // Login link
    QLabel *loginText = new QLabel("Already have an account? <a href=\"#\">Login</a>");
    loginText->setTextFormat(Qt::RichText);
    loginText->setTextInteractionFlags(Qt::TextBrowserInteraction);
    loginText->setOpenExternalLinks(false);
    loginText->setAlignment(Qt::AlignCenter);
    loginText->setObjectName("loginLink");
    connect(loginText, &QLabel::linkActivated, this, [this](const QString &){ emit loginRequested(); });

    // Form layout
    QVBoxLayout *formLayout = new QVBoxLayout;
    formLayout->setAlignment(Qt::AlignCenter);
    formLayout->setSpacing(8);
    formLayout->addWidget(headingLabel);
    formLayout->addSpacing(24);
    formLayout->addWidget(usernameLabel, 0, Qt::AlignLeft);
    formLayout->addWidget(usernameEdit, 0, Qt::AlignLeft);
    formLayout->addSpacing(16);
    formLayout->addWidget(passwordLabel, 0, Qt::AlignLeft);
    formLayout->addWidget(passwordEdit, 0, Qt::AlignLeft);
    formLayout->addSpacing(16);
    formLayout->addWidget(confirmPasswordLabel, 0, Qt::AlignLeft);
    formLayout->addWidget(confirmPasswordEdit, 0, Qt::AlignLeft);
    formLayout->addSpacing(16);
    formLayout->addWidget(errorLabel, 0, Qt::AlignCenter);
    formLayout->addWidget(signUpButton, 0, Qt::AlignLeft);
    formLayout->addSpacing(16);
    formLayout->addWidget(loginText, 0, Qt::AlignCenter);

    QWidget *formBox = new QWidget;
    formBox->setLayout(formLayout);
    formBox->setObjectName("signUpPanel");

    // Main layout
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

void SignUpView::resetFieldStyles() {
    usernameEdit->setStyleSheet("");
    passwordEdit->setStyleSheet("");
    confirmPasswordEdit->setStyleSheet("");
}

void SignUpView::clearFields() {
    usernameEdit->clear();
    passwordEdit->clear();
    confirmPasswordEdit->clear();
    errorLabel->hide();
    resetFieldStyles();
}

void SignUpView::handleSignUp() {
    resetFieldStyles();
    emit signUpRequested(getUsername(), getPassword(), getConfirmPassword());
}

void SignUpView::showError(const QString &message) {
    errorLabel->setText(message);
    errorLabel->show();

    if (message.contains("username", Qt::CaseInsensitive)) {
        usernameEdit->setStyleSheet("QLineEdit { border: 1px solid #D32F2F; }");
    }
    if (message.contains("password", Qt::CaseInsensitive)) {
        passwordEdit->setStyleSheet("QLineEdit { border: 1px solid #D32F2F; }");
        confirmPasswordEdit->setStyleSheet("QLineEdit { border: 1px solid #D32F2F; }");
    }
}

void SignUpView::hideError() {
    errorLabel->hide();
}

void SignUpView::paintEvent(QPaintEvent *event) {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.fillRect(rect(), QColor("#121212"));
    QWidget::paintEvent(event);
}