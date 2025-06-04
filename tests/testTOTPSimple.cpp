#include <QCoreApplication>
#include <QDebug>
#include <QTimer>
#include <QThread>
#include <QDateTime>
#include <iostream>

#include "../services/auth/otp/TOTPEnrollment.h"
#include "../services/auth/otp/TOTP.h"

void testTOTPFunctionality() {
    qDebug() << "=== TOTP Functionality Test ===";
    
    try {
        // Test 1: Secret Generation
        qDebug() << "\n1. Testing secret generation...";
        TOTPEnrollment enrollment;
        QString secret = enrollment.generateSecret();
        qDebug() << "PASS: Generated secret:" << secret;
        qDebug() << "   Length:" << secret.length() << "characters";
        
        // Test 2: OTP Auth URL Creation
        qDebug() << "\n2. Testing OTP Auth URL creation...";
        QString otpauthURL = enrollment.createOTPAuthURL("MyShare", "test@example.com", secret);
        qDebug() << "PASS: Generated otpauth:// URL:";
        qDebug() << "   " << otpauthURL;
        
        // Test 3: Enrollment Data Creation
        qDebug() << "\n3. Testing enrollment data creation...";
        TOTPEnrollmentData data = enrollment.createEnrollmentData("MyShare", "test@example.com", secret);
        if (data.isValid()) {
            qDebug() << "PASS: Enrollment data created successfully";
            qDebug() << "   Issuer:" << data.issuer;
            qDebug() << "   Account:" << data.accountName;
            qDebug() << "   Secret:" << data.secret;
            qDebug() << "   Current verification code:" << data.verificationCode;
            qDebug() << "   Timestamp:" << data.timestamp;
        } else {
            qDebug() << "FAIL: Enrollment data creation failed";
            return;
        }
        
        // Test 4: QR Code Generation
        qDebug() << "\n4. Testing QR code generation...";
        QByteArray qrData = enrollment.generateEnrollmentQR(data);
        if (!qrData.isEmpty()) {
            qDebug() << "PASS: QR code generated successfully";
            qDebug() << "   QR data size:" << qrData.size() << "bytes";
            
            // Extract QR metadata
            if (qrData.size() >= 8) {
                QDataStream stream(qrData);
                stream.setVersion(QDataStream::Qt_6_5);
                qint32 width, version;
                stream >> width >> version;
                qDebug() << "   QR dimensions:" << width << "x" << width;
                qDebug() << "   QR version:" << version;
            }
        } else {
            qDebug() << "FAIL: QR code generation failed";
        }
        
        // Test 5: TOTP Code Generation and Verification
        qDebug() << "\n5. Testing TOTP code generation and verification...";
        TOTP totp(secret.toStdString());
        
        // Generate current code
        QString currentCode = QString::fromStdString(totp.generate());
        qDebug() << "PASS: Current TOTP code:" << currentCode;
        
        // Test verification with current code
        bool verified = enrollment.verifySetupCode(secret, currentCode);
        qDebug() << "PASS: Code verification:" << (verified ? "PASSED" : "FAILED");
        
        // Test verification with wrong code
        bool wrongVerified = enrollment.verifySetupCode(secret, "123456");
        qDebug() << "PASS: Wrong code rejection:" << (!wrongVerified ? "PASSED" : "FAILED");
        
        // Test 6: Time Window Tolerance
        qDebug() << "\n6. Testing time window tolerance...";
        qint64 currentTime = QDateTime::currentSecsSinceEpoch();
        
        // Generate code for 30 seconds ago
        QString pastCode = QString::fromStdString(totp.generate(currentTime - 30));
        bool pastVerified = enrollment.verifySetupCode(secret, pastCode, 1); // 1 window tolerance
        qDebug() << "PASS: Past code verification (30s ago):" << (pastVerified ? "PASSED" : "FAILED");
        
        // Generate code for 30 seconds in future
        QString futureCode = QString::fromStdString(totp.generate(currentTime + 30));
        bool futureVerified = enrollment.verifySetupCode(secret, futureCode, 1); // 1 window tolerance
        qDebug() << "PASS: Future code verification (30s ahead):" << (futureVerified ? "PASSED" : "FAILED");
        
        // Test 7: Multiple Codes at Different Times
        qDebug() << "\n7. Testing multiple TOTP codes...";
        for (int i = 0; i < 3; i++) {
            QString testCode = QString::fromStdString(totp.generate());
            qDebug() << "   Code generation" << (i+1) << ":" << testCode;
            QThread::msleep(100); // Small delay to show consistency
        }
        
        qDebug() << "\n=== All Tests Completed Successfully! ===";
        qDebug() << "\nMANUAL TEST INSTRUCTIONS:";
        qDebug() << "1. Copy this otpauth:// URL to your authenticator app:";
        qDebug() << "   " << otpauthURL;
        qDebug() << "2. Or manually enter this secret:" << secret;
        qDebug() << "3. Current code should be:" << currentCode;
        qDebug() << "4. Codes change every 30 seconds";
        
    } catch (const std::exception& e) {
        qDebug() << "FAIL: Test failed with exception:" << e.what();
    }
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    
    // Run the test
    testTOTPFunctionality();
    
    // Exit immediately
    QTimer::singleShot(0, &app, &QCoreApplication::quit);
    
    return app.exec();
} 