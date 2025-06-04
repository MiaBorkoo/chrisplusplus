#include "TOTPCodeDialog.h"
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFont>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QTimer>

TOTPCodeDialog::TOTPCodeDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Two-Factor Authentication");
    setModal(true);
    setFixedSize(400, 200);
    
    setupUI();
    styleComponents();
}

void TOTPCodeDialog::setupUI() {
    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setSpacing(15);
    m_mainLayout->setContentsMargins(20, 20, 20, 20);
    
    // Title
    m_titleLabel = new QLabel("Enter Authentication Code");
    m_titleLabel->setAlignment(Qt::AlignCenter);
    
    // Instructions
    m_instructionLabel = new QLabel("Enter the 6-digit code from your authenticator app:");
    m_instructionLabel->setWordWrap(true);
    m_instructionLabel->setAlignment(Qt::AlignCenter);
    
    // Code input
    m_codeInput = new QLineEdit();
    m_codeInput->setPlaceholderText("000000");
    m_codeInput->setMaxLength(6);
    m_codeInput->setAlignment(Qt::AlignCenter);
    
    // Set up validator for 6-digit numeric input
    QRegularExpression regExp("\\d{0,6}");
    QRegularExpressionValidator *validator = new QRegularExpressionValidator(regExp, this);
    m_codeInput->setValidator(validator);
    
    // Buttons
    m_buttonLayout = new QHBoxLayout();
    m_cancelButton = new QPushButton("Cancel");
    m_verifyButton = new QPushButton("Verify");
    m_verifyButton->setEnabled(false); // Disabled until valid code entered
    m_verifyButton->setDefault(true);  // Make this the default button
    
    m_buttonLayout->addWidget(m_cancelButton);
    m_buttonLayout->addStretch();
    m_buttonLayout->addWidget(m_verifyButton);
    
    // Error label
    m_errorLabel = new QLabel();
    m_errorLabel->setVisible(false);
    m_errorLabel->setAlignment(Qt::AlignCenter);
    
    // Add to main layout
    m_mainLayout->addWidget(m_titleLabel);
    m_mainLayout->addWidget(m_instructionLabel);
    m_mainLayout->addWidget(m_codeInput);
    m_mainLayout->addWidget(m_errorLabel);
    m_mainLayout->addLayout(m_buttonLayout);
    
    // Connect signals
    connect(m_verifyButton, &QPushButton::clicked, this, &TOTPCodeDialog::handleVerifyClicked);
    connect(m_cancelButton, &QPushButton::clicked, this, &TOTPCodeDialog::handleCancelClicked);
    connect(m_codeInput, &QLineEdit::textChanged, this, &TOTPCodeDialog::onCodeChanged);
    connect(m_codeInput, &QLineEdit::returnPressed, this, &TOTPCodeDialog::handleVerifyClicked);
    
    // Focus on code input
    m_codeInput->setFocus();
}

void TOTPCodeDialog::styleComponents() {
    // Title styling
    QFont titleFont;
    titleFont.setPointSize(14);
    titleFont.setBold(true);
    m_titleLabel->setFont(titleFont);
    
    // Code input styling - larger and centered
    m_codeInput->setStyleSheet(
        "QLineEdit {"
        "    padding: 12px;"
        "    font-size: 20px;"
        "    font-family: monospace;"
        "    letter-spacing: 4px;"
        "    text-align: center;"
        "    border: 2px solid #ddd;"
        "    border-radius: 5px;"
        "    background-color: #f9f9f9;"
        "}"
        "QLineEdit:focus {"
        "    border-color: #4CAF50;"
        "    background-color: white;"
        "}"
    );
    
    // Button styling
    m_verifyButton->setStyleSheet(
        "QPushButton {"
        "    background-color: #4CAF50;"
        "    color: white;"
        "    padding: 8px 16px;"
        "    border: none;"
        "    border-radius: 4px;"
        "    font-weight: bold;"
        "    min-width: 80px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #45a049;"
        "}"
        "QPushButton:disabled {"
        "    background-color: #cccccc;"
        "    color: #666666;"
        "}"
    );
    
    m_cancelButton->setStyleSheet(
        "QPushButton {"
        "    background-color: #f44336;"
        "    color: white;"
        "    padding: 8px 16px;"
        "    border: none;"
        "    border-radius: 4px;"
        "    min-width: 80px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #da190b;"
        "}"
    );
    
    // Error label styling
    m_errorLabel->setStyleSheet("color: red; font-weight: bold;");
}

QString TOTPCodeDialog::getCode() const {
    return m_codeInput->text();
}

void TOTPCodeDialog::showError(const QString &message) {
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(true);
}

void TOTPCodeDialog::clearError() {
    m_errorLabel->clear();
    m_errorLabel->setVisible(false);
}

void TOTPCodeDialog::clearCode() {
    m_codeInput->clear();
}

void TOTPCodeDialog::setVerificationInProgress(bool inProgress) {
    m_verifyButton->setEnabled(!inProgress && m_codeInput->text().length() == 6);
    m_cancelButton->setEnabled(!inProgress);
    m_codeInput->setEnabled(!inProgress);
    
    if (inProgress) {
        m_verifyButton->setText("Verifying...");
    } else {
        m_verifyButton->setText("Verify");
    }
}

void TOTPCodeDialog::handleVerifyClicked() {
    clearError();
    
    QString code = m_codeInput->text();
    if (code.length() != 6) {
        showError("Please enter a 6-digit code");
        return;
    }
    
    emit codeEntered(code);
}

void TOTPCodeDialog::handleCancelClicked() {
    reject(); // Close dialog with rejected result
}

void TOTPCodeDialog::onCodeChanged() {
    // Enable verify button only when 6 digits are entered
    bool isValid = m_codeInput->text().length() == 6;
    m_verifyButton->setEnabled(isValid);
    
    // Clear any previous errors when user starts typing
    if (!m_codeInput->text().isEmpty()) {
        clearError();
    }
    
    // Auto-submit when 6 digits are entered (optional UX improvement)
    if (isValid) {
        // Small delay to let user see the complete code before submitting
        QTimer::singleShot(500, this, &TOTPCodeDialog::handleVerifyClicked);
    }
} 