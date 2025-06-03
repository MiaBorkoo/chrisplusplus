#include "AccountSection.h"
#include <QVBoxLayout>
#include <QMessageBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>

AccountSection::AccountSection(QWidget *parent) : QWidget(parent) {
    setWindowFlags(Qt::Popup);  //makes this widget act like a dropdown popup
    setFixedSize(300, 350);

    setObjectName("accountSection"); 

    QLabel* headingLabel = new QLabel("Change Your Account Password");
    headingLabel->setObjectName("accountHeading");
    headingLabel->setAlignment(Qt::AlignCenter);

    m_usernameLabel = new QLabel("Username: ");
    m_oldPassword = new QLineEdit();
    m_oldPassword->setObjectName("accountOldPassword"); 
    m_oldPassword->setEchoMode(QLineEdit::Normal);
    m_oldPassword->setPlaceholderText("Old Password");

    m_newPassword = new QLineEdit();
    m_newPassword->setObjectName("accountNewPassword");
    m_newPassword->setEchoMode(QLineEdit::Normal);
    m_newPassword->setPlaceholderText("New Password");

    m_confirmPassword = new QLineEdit();
    m_confirmPassword->setObjectName("accountConfirmPassword");
    m_confirmPassword->setEchoMode(QLineEdit::Normal);
    m_confirmPassword->setPlaceholderText("Confirm Password");

    m_changePasswordBtn = new QPushButton("Change Password");
    m_changePasswordBtn->setObjectName("saveAccountButton"); 

    m_successLabel = new QLabel("Password changed successfully!");
    m_successLabel->setObjectName("passwordSuccessLabel");
    m_successLabel->setStyleSheet("color: #43A047; font-size: 13px;");
    m_successLabel->setVisible(false);

    m_errorLabel = new QLabel();
    m_errorLabel->setStyleSheet("color: red; font-size: 13px;");
    m_errorLabel->setVisible(false);
   


    connect(m_changePasswordBtn, &QPushButton::clicked, this, &AccountSection::onChangePasswordClicked);

    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->addWidget(headingLabel);
    layout->addWidget(m_usernameLabel);
    layout->addWidget(m_oldPassword);
    layout->addWidget(m_newPassword);
    layout->addWidget(m_confirmPassword);
    layout->addWidget(m_changePasswordBtn);;
    layout->addWidget(m_successLabel);
    layout->addWidget(m_errorLabel);
}

void AccountSection::setUsername(const QString& username) {
    m_usernameLabel->setText("Username: " + username);
}

void AccountSection::onChangePasswordClicked() {
    m_errorLabel->setVisible(false); // hide error by default

    if (m_newPassword->text() != m_confirmPassword->text()) {
        m_errorLabel->setText("New passwords do not match");
        m_errorLabel->setVisible(true);
        clearFields();
        return;
    }

    emit changePasswordRequested(m_oldPassword->text(), m_newPassword->text());
}

void AccountSection::clearFields() {
    m_oldPassword->clear();
    m_newPassword->clear();
    m_confirmPassword->clear();
}

void AccountSection::showErrorMessage(const QString& message) {
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(true);
}