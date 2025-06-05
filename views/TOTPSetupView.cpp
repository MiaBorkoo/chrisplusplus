#include "TOTPSetupView.h"
#include "../controllers/TOTPController.h"
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
#include <QDebug>
#include <QFile>

TOTPSetupView::TOTPSetupView(QWidget *parent)
    : QWidget(parent), m_controller(nullptr)
{
    setupUI();
    loadStyles();
}

void TOTPSetupView::setupUI() {
    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setSpacing(20);
    m_mainLayout->setContentsMargins(40, 40, 40, 40);
    
    // Title
    m_titleLabel = new QLabel("Set Up Two-Factor Authentication");
    m_titleLabel->setObjectName("totpSetupTitle");
    m_titleLabel->setAlignment(Qt::AlignCenter);
    
    // Instructions
    m_instructionLabel = new QLabel(
        "1. Install Google Authenticator or similar app on your phone\n"
        "2. Scan the QR code below with your authenticator app\n"
        "3. Enter the 6-digit code from your app to complete setup"
    );
    m_instructionLabel->setObjectName("totpSetupInstructions");
    m_instructionLabel->setWordWrap(true);
    m_instructionLabel->setAlignment(Qt::AlignLeft);
    
    // QR Code display
    m_stepLabel = new QLabel("Scan this QR code:");
    m_qrCodeLabel = new QLabel("QR Code will appear here...");
    m_qrCodeLabel->setObjectName("totpQRCodeLabel");
    m_qrCodeLabel->setAlignment(Qt::AlignCenter);
    m_qrCodeLabel->setMinimumSize(250, 250);
    
    // Code input
    QLabel *codeLabel = new QLabel("Enter 6-digit code:");
    m_codeInput = new QLineEdit();
    m_codeInput->setObjectName("totpSetupCodeInput");
    m_codeInput->setPlaceholderText("000000");
    m_codeInput->setMaxLength(6);
    
    // Set up validator for 6-digit numeric input
    QRegularExpression regExp("\\d{0,6}");
    QRegularExpressionValidator *validator = new QRegularExpressionValidator(regExp, this);
    m_codeInput->setValidator(validator);
    
    // Buttons
    m_buttonLayout = new QHBoxLayout();
    m_cancelButton = new QPushButton("Cancel");
    m_cancelButton->setObjectName("totpSetupCancelButton");
    m_verifyButton = new QPushButton("Verify & Complete Setup");
    m_verifyButton->setObjectName("totpSetupVerifyButton");
    m_verifyButton->setEnabled(false); // Disabled until valid code entered
    
    m_buttonLayout->addWidget(m_cancelButton);
    m_buttonLayout->addStretch();
    m_buttonLayout->addWidget(m_verifyButton);
    
    // Error label
    m_errorLabel = new QLabel();
    m_errorLabel->setObjectName("totpErrorLabel");
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

void TOTPSetupView::loadStyles() {
    // Load styles from CSS file
    QFile styleFile(":/styles/styles.css");
    if (styleFile.open(QIODevice::ReadOnly)) {
        QString style = styleFile.readAll();
        this->setStyleSheet(style);
    }
}

void TOTPSetupView::setController(TOTPController *controller) {
    m_controller = controller;
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
    QString code = m_codeInput->text().trimmed();
    
    qDebug() << "TOTPSetupView: Verify clicked with code:" << code;
    
    if (code.length() != 6) {
        showError("Please enter a 6-digit code");
        return;
    }
    
    // Clear any previous errors
    clearError();
    
    // Call controller instead of emitting signal
    if (m_controller) {
        m_controller->verifyCode(code);
    }
}

void TOTPSetupView::handleCancelClicked() {
    // Call controller instead of emitting signal
    if (m_controller) {
        m_controller->cancelCodeEntry();
    }
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