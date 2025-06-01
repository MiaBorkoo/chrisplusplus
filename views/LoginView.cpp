#include "LoginView.h"
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFont>
#include <QFrame>
#include <QPalette>
#include <QPropertyAnimation>
#include <QGraphicsOpacityEffect>
#include <QTimer>
#include <QPainter>
#include <QFile>
#include <QApplication>
#include <QStyle>

class GradientWidget : public QWidget {
protected:
    void paintEvent(QPaintEvent *) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);

        //gradient with just two colors
        QLinearGradient gradient(0, 0, width(), height());
        gradient.setColorAt(0, QColor("#23a6d5"));
        gradient.setColorAt(1, QColor("#23d5ab"));

        //this fills the widget with the gradient
        painter.fillRect(rect(), gradient);
    }
};

LoginView::LoginView(QWidget *parent) : QWidget(parent)
{
    QFont headingFont("Helvetica Neue", 48, QFont::Bold);
    QFont labelFont("Arial", 12, QFont::Bold);
    QFont inputFont("Arial", 11);
    QFont buttonFont("Arial", 11, QFont::Bold);

    QLabel *logoLabel = new QLabel;
    logoLabel->setPixmap(QPixmap(":/assets/logo.png").scaled(100, 100, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    logoLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    logoLabel->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

    // left panel -> login panel
    QLabel *loginHeading = new QLabel("Login to Your Account");
    loginHeading->setObjectName("loginHeading");
    loginHeading->setFont(headingFont);
    loginHeading->setAlignment(Qt::AlignCenter);

    usernameLabel = new QLabel("Username:");
    usernameLabel->setObjectName("usernameLabel");
    usernameLabel->setFont(labelFont);
    usernameEdit = new QLineEdit;
    usernameEdit->setFont(inputFont);
    usernameEdit->setFixedSize(250, 40);
    usernameEdit->setAlignment(Qt::AlignCenter);
    usernameEdit->setPlaceholderText("Enter username");

    passwordLabel = new QLabel("Password:");
    passwordLabel->setObjectName("passwordLabel");
    passwordLabel->setFont(labelFont);
    passwordEdit = new QLineEdit;
    passwordEdit->setFont(inputFont);
    passwordEdit->setFixedSize(250, 40);
    passwordEdit->setAlignment(Qt::AlignCenter);
    passwordEdit->setPlaceholderText("Enter password");
    passwordEdit->setEchoMode(QLineEdit::Password);

    loginButton = new QPushButton("Login");
    loginButton->setObjectName("loginButton");
    loginButton->setFont(buttonFont);
    loginButton->setFixedSize(250, 40);
    connect(loginButton, &QPushButton::clicked, this, &LoginView::handleLogin);

    QVBoxLayout *formLayout = new QVBoxLayout;
    formLayout->setAlignment(Qt::AlignCenter);
    formLayout->addWidget(usernameLabel, 0, Qt::AlignCenter);
    formLayout->addWidget(usernameEdit, 0, Qt::AlignCenter);
    formLayout->addWidget(passwordLabel, 0, Qt::AlignCenter);
    formLayout->addWidget(passwordEdit, 0, Qt::AlignCenter);
    formLayout->addSpacing(10);
    formLayout->addWidget(loginButton, 0, Qt::AlignCenter);

    QVBoxLayout *loginSectionLayout = new QVBoxLayout;
    loginSectionLayout->addWidget(loginHeading);
    loginSectionLayout->addSpacing(30);
    loginSectionLayout->addLayout(formLayout);

    QVBoxLayout *leftLayout = new QVBoxLayout;
    leftLayout->addWidget(logoLabel, 0, Qt::AlignLeft | Qt::AlignTop);
    leftLayout->addSpacing(10);
    leftLayout->addStretch(); //pushes the login section down
    leftLayout->addLayout(loginSectionLayout);
    leftLayout->addStretch(); //pushes the login section up from the bottom

    QWidget *leftWidget = new QWidget;
    leftWidget->setObjectName("leftPanel");
    leftWidget->setAutoFillBackground(true);
    QPalette leftPalette;
    leftPalette.setColor(QPalette::Window, Qt::black);
    leftWidget->setPalette(leftPalette);
    leftWidget->setLayout(leftLayout);

    // right panel -> sign-up panel
    GradientWidget *rightWidget = new GradientWidget;
    rightWidget->setObjectName("rightPanel");
    
    QLabel *newHereLabel = new QLabel("New here?");
    newHereLabel->setObjectName("newHereLabel");
    newHereLabel->setFont(headingFont);
    newHereLabel->setAlignment(Qt::AlignCenter);

    QLabel *textsLabel = new QLabel("Sign up and discover a great amount of new opportunities!");
    QFont regularFont("Arial", 12);
    textsLabel->setFont(regularFont);
    textsLabel->setStyleSheet("color: white;");
    textsLabel->setAlignment(Qt::AlignCenter);

    signUpButton = new QPushButton("Sign Up");
    signUpButton->setObjectName("signUpButton");
    signUpButton->setFont(buttonFont);
    signUpButton->setFixedSize(250, 40);
    connect(signUpButton, &QPushButton::clicked, this, &LoginView::handleSignUp);

    QVBoxLayout *rightLayout = new QVBoxLayout;
    rightLayout->addStretch();
    rightLayout->addWidget(newHereLabel);
    rightLayout->addSpacing(30);
    rightLayout->addWidget(textsLabel);
    rightLayout->addSpacing(20);
    rightLayout->addWidget(signUpButton, 0, Qt::AlignCenter);
    rightLayout->addStretch();

    rightWidget->setLayout(rightLayout);

    //Main layout
    QHBoxLayout *mainLayout = new QHBoxLayout(this);
    mainLayout->addWidget(leftWidget, 3);
    mainLayout->addWidget(rightWidget, 1);
    setLayout(mainLayout);

    rightWidget->setMinimumWidth(200);
    setWindowTitle("Login");
    resize(800, 500);
}

QString LoginView::getUsername() const
{
    return usernameEdit->text();
}

QString LoginView::getPassword() const
{
    return passwordEdit->text();
}

void LoginView::showError(const QString &message)
{
    if (message.contains("username", Qt::CaseInsensitive)) {
        usernameEdit->setStyleSheet("border: 2px solid #ff4444; border-radius: 20px; background: white; color: black; padding: 10px; font-size: 11px;");
        usernameEdit->setPlaceholderText("Username is required");
    }
    
    if (message.contains("password", Qt::CaseInsensitive)) {
        passwordEdit->setStyleSheet("border: 2px solid #ff4444; border-radius: 20px; background: white; color: black; padding: 10px; font-size: 11px;");
        passwordEdit->setPlaceholderText("Password is required");
    }
}

void LoginView::clearFields()
{
    usernameEdit->clear();
    passwordEdit->clear();
    
    usernameEdit->setStyleSheet("");
    passwordEdit->setStyleSheet("");
    usernameEdit->setPlaceholderText("Enter username");
    passwordEdit->setPlaceholderText("Enter password");
    
    usernameEdit->update();
    passwordEdit->update();
}

void LoginView::handleLogin()
{
    QString username = usernameEdit->text();
    QString password = passwordEdit->text();
    emit loginAttempted(username, password);
}

void LoginView::handleSignUp()
{
    emit signUpClicked();
}