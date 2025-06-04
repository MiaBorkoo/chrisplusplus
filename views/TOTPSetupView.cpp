#include "TOTPSetupView.h"
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPixmap>
#include <QPainter>
#include <QByteArray>
#include <QBuffer>
#include <QDataStream>
#include <QFont>
#include <QRegularExpression>
#include <QRegularExpressionValidator>

TOTPSetupView::TOTPSetupView(QWidget *parent)
    : QWidget(parent)
{
    setupUI();
    styleComponents();
}

void TOTPSetupView::setupUI() {
    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setSpacing(20);
    m_mainLayout->setContentsMargins(40, 40, 40, 40);
    
    // Title
    m_titleLabel = new QLabel("Set Up Two-Factor Authentication");
    m_titleLabel->setAlignment(Qt::AlignCenter);
    
    // Instructions
    m_instructionLabel = new QLabel(
        "1. Install Google Authenticator or similar app on your phone\n"
        "2. Scan the QR code below with your authenticator app\n"
        "3. Enter the 6-digit code from your app to complete setup"
    );
    m_instructionLabel->setWordWrap(true);
    m_instructionLabel->setAlignment(Qt::AlignLeft);
    
    // QR Code display
    m_stepLabel = new QLabel("Scan this QR code:");
    m_qrCodeLabel = new QLabel("QR Code will appear here...");
    m_qrCodeLabel->setAlignment(Qt::AlignCenter);
    m_qrCodeLabel->setMinimumSize(250, 250);
    m_qrCodeLabel->setStyleSheet("border: 1px solid #ccc; background-color: white;");
    
    // Code input
    QLabel *codeLabel = new QLabel("Enter 6-digit code:");
    m_codeInput = new QLineEdit();
    m_codeInput->setPlaceholderText("000000");
    m_codeInput->setMaxLength(6);
    
    // Set up validator for 6-digit numeric input
    QRegularExpression regExp("\\d{0,6}");
    QRegularExpressionValidator *validator = new QRegularExpressionValidator(regExp, this);
    m_codeInput->setValidator(validator);
    
    // Buttons
    m_buttonLayout = new QHBoxLayout();
    m_cancelButton = new QPushButton("Cancel");
    m_verifyButton = new QPushButton("Verify & Complete Setup");
    m_verifyButton->setEnabled(false); // Disabled until valid code entered
    
    m_buttonLayout->addWidget(m_cancelButton);
    m_buttonLayout->addStretch();
    m_buttonLayout->addWidget(m_verifyButton);
    
    // Error label
    m_errorLabel = new QLabel();
    m_errorLabel->setVisible(false);
    
    // Add to main layout
    m_mainLayout->addWidget(m_titleLabel);
    m_mainLayout->addWidget(m_instructionLabel);
    m_mainLayout->addWidget(m_stepLabel);
    m_mainLayout->addWidget(m_qrCodeLabel);
    m_mainLayout->addWidget(codeLabel);
    m_mainLayout->addWidget(m_codeInput);
    m_mainLayout->addWidget(m_errorLabel);
    m_mainLayout->addLayout(m_buttonLayout);
    m_mainLayout->addStretch();
    
    // Connect signals
    connect(m_verifyButton, &QPushButton::clicked, this, &TOTPSetupView::handleVerifyClicked);
    connect(m_cancelButton, &QPushButton::clicked, this, &TOTPSetupView::handleCancelClicked);
    connect(m_codeInput, &QLineEdit::textChanged, this, &TOTPSetupView::onCodeChanged);
}

void TOTPSetupView::styleComponents() {
    // Title styling
    QFont titleFont;
    titleFont.setPointSize(18);
    titleFont.setBold(true);
    m_titleLabel->setFont(titleFont);
    
    // Instruction styling
    QFont instructionFont;
    instructionFont.setPointSize(11);
    m_instructionLabel->setFont(instructionFont);
    
    // Code input styling
    m_codeInput->setStyleSheet(
        "QLineEdit {"
        "    padding: 8px;"
        "    font-size: 16px;"
        "    font-family: monospace;"
        "    letter-spacing: 2px;"
        "    text-align: center;"
        "    border: 2px solid #ddd;"
        "    border-radius: 5px;"
        "}"
        "QLineEdit:focus {"
        "    border-color: #4CAF50;"
        "}"
    );
    
    // Button styling
    m_verifyButton->setStyleSheet(
        "QPushButton {"
        "    background-color: #4CAF50;"
        "    color: white;"
        "    padding: 10px 20px;"
        "    border: none;"
        "    border-radius: 5px;"
        "    font-weight: bold;"
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
        "    padding: 10px 20px;"
        "    border: none;"
        "    border-radius: 5px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #da190b;"
        "}"
    );
    
    // Error label styling
    m_errorLabel->setStyleSheet("color: red; font-weight: bold;");
}

void TOTPSetupView::displayQRCode(const QString &qrCodeBase64) {
    QPixmap qrPixmap = convertBase64ToQRImage(qrCodeBase64);
    
    if (!qrPixmap.isNull()) {
        // Scale QR code to fit label while maintaining aspect ratio
        QPixmap scaledPixmap = qrPixmap.scaled(200, 200, Qt::KeepAspectRatio, Qt::SmoothTransformation);
        m_qrCodeLabel->setPixmap(scaledPixmap);
        m_stepLabel->setText("Scan this QR code with your authenticator app:");
    } else {
        m_qrCodeLabel->setText("Failed to display QR code");
        showError("Failed to generate QR code. Please try again.");
    }
}

QPixmap TOTPSetupView::convertBase64ToQRImage(const QString &base64Data) {
    // Decode base64 data
    QByteArray qrData = QByteArray::fromBase64(base64Data.toUtf8());
    
    if (qrData.isEmpty()) {
        return QPixmap();
    }
    
    // Extract metadata and image data
    QDataStream stream(qrData);
    qint32 width, version;
    stream >> width >> version;
    
    // Calculate remaining data for QR matrix
    int headerSize = sizeof(qint32) * 2;
    QByteArray matrixData = qrData.mid(headerSize);
    
    if (matrixData.size() != width * width) {
        return QPixmap();
    }
    
    // Create QR code image
    QPixmap pixmap(width * 4, width * 4); // Scale up 4x for better visibility
    pixmap.fill(Qt::white);
    
    QPainter painter(&pixmap);
    painter.setBrush(Qt::black);
    painter.setPen(Qt::NoPen);
    
    for (int y = 0; y < width; ++y) {
        for (int x = 0; x < width; ++x) {
            if (matrixData.at(y * width + x) & 1) {
                painter.drawRect(x * 4, y * 4, 4, 4);
            }
        }
    }
    
    return pixmap;
}

void TOTPSetupView::showError(const QString &message) {
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(true);
}

void TOTPSetupView::clearError() {
    m_errorLabel->clear();
    m_errorLabel->setVisible(false);
}

void TOTPSetupView::clearCode() {
    m_codeInput->clear();
}

QString TOTPSetupView::getVerificationCode() const {
    return m_codeInput->text();
}

void TOTPSetupView::setSetupInProgress(bool inProgress) {
    m_verifyButton->setEnabled(!inProgress && m_codeInput->text().length() == 6);
    m_cancelButton->setEnabled(!inProgress);
    m_codeInput->setEnabled(!inProgress);
    
    if (inProgress) {
        m_verifyButton->setText("Verifying...");
    } else {
        m_verifyButton->setText("Verify & Complete Setup");
    }
}

void TOTPSetupView::handleVerifyClicked() {
    clearError();
    
    QString code = m_codeInput->text();
    if (code.length() != 6) {
        showError("Please enter a 6-digit code");
        return;
    }
    
    emit verificationCodeEntered(code);
}

void TOTPSetupView::handleCancelClicked() {
    emit setupCancelled();
}

void TOTPSetupView::onCodeChanged() {
    // Enable verify button only when 6 digits are entered
    bool isValid = m_codeInput->text().length() == 6;
    m_verifyButton->setEnabled(isValid);
    
    // Clear any previous errors when user starts typing
    if (!m_codeInput->text().isEmpty()) {
        clearError();
    }
} 