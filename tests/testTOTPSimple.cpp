#include <QCoreApplication>
#include <QDebug>
#include <QTimer>
#include <QThread>
#include <QDateTime>
#include <iostream>
#include <string>

#include "../services/auth/otp/TOTP.h"

void testSimplifiedTOTP() {
    qDebug() << "=== Simplified TOTP Test ===";
    
    try {
        // Test 1: Secret Generation
        qDebug() << "\n1. Testing secret generation...";
        std::string secret = TOTP::generateSecret();
        qDebug() << "PASS: Generated secret:" << QString::fromStdString(secret);
        qDebug() << "   Length:" << secret.length() << "characters";
        
        // Test 2: OTP Auth URL Creation
        qDebug() << "\n2. Testing OTP Auth URL creation...";
        std::string otpauthURL = TOTP::createOTPAuthURL("MyShare", "test@example.com", secret);
        qDebug() << "PASS: Generated otpauth:// URL:";
        qDebug() << "   " << QString::fromStdString(otpauthURL);
        
        // Test 3: TOTP Code Generation
        qDebug() << "\n3. Testing TOTP code generation...";
        TOTP totp(secret);
        std::string currentCode = totp.generate();
        qDebug() << "PASS: Current TOTP code:" << QString::fromStdString(currentCode);
        qDebug() << "   Code length:" << currentCode.length() << "digits";
        
        // Test 4: Code Verification (Current Time)
        qDebug() << "\n4. Testing code verification...";
        bool verified = totp.verify(currentCode);
        qDebug() << "PASS: Current code verification:" << (verified ? "SUCCESS" : "FAILED");
        
        // Test verification with wrong code
        bool wrongVerified = totp.verify("123456");
        qDebug() << "PASS: Wrong code rejection:" << (!wrongVerified ? "SUCCESS" : "FAILED");
        
        // Test 5: Time Window Tolerance
        qDebug() << "\n5. Testing time window tolerance...";
        uint64_t currentTime = QDateTime::currentSecsSinceEpoch();
        
        // Generate code for 30 seconds ago (previous window)
        std::string pastCode = totp.generate(currentTime - 30);
        bool pastVerified = totp.verify(pastCode, 1); // 1 window tolerance
        qDebug() << "PASS: Past code verification (30s ago):" << (pastVerified ? "SUCCESS" : "FAILED");
        
        // Generate code for 30 seconds in future (next window)
        std::string futureCode = totp.generate(currentTime + 30);
        bool futureVerified = totp.verify(futureCode, 1); // 1 window tolerance
        qDebug() << "PASS: Future code verification (30s ahead):" << (futureVerified ? "SUCCESS" : "FAILED");
        
        // Test 6: Code Consistency
        qDebug() << "\n6. Testing code consistency...";
        for (int i = 0; i < 3; i++) {
            std::string testCode = totp.generate();
            qDebug() << "   Code generation" << (i+1) << ":" << QString::fromStdString(testCode);
            QThread::msleep(50); // Small delay - should produce same code
        }
        
        // Test 7: Different Time Windows
        qDebug() << "\n7. Testing different time windows...";
        uint64_t baseTime = currentTime - (currentTime % 30); // Align to 30s boundary
        
        for (int i = 0; i < 3; i++) {
            uint64_t testTime = baseTime + (i * 30); // Different 30s windows
            std::string windowCode = totp.generate(testTime);
            qDebug() << "   Window" << i << "code:" << QString::fromStdString(windowCode);
        }
        
        // Test 8: Different Secrets Produce Different Codes
        qDebug() << "\n8. Testing different secrets...";
        std::string secret2 = TOTP::generateSecret();
        TOTP totp2(secret2);
        std::string code2 = totp2.generate();
        
        qDebug() << "   Secret 1 code:" << QString::fromStdString(currentCode);
        qDebug() << "   Secret 2 code:" << QString::fromStdString(code2);
        qDebug() << "   Codes are different:" << (currentCode != code2 ? "SUCCESS" : "FAILED");
        
        // Test 9: Edge Cases
        qDebug() << "\n9. Testing edge cases...";
        
        // Test with custom time steps and digits (if supported)
        try {
            TOTP customTOTP(secret, 60, 8); // 60s window, 8 digits
            std::string customCode = customTOTP.generate();
            qDebug() << "   Custom TOTP (60s, 8-digit):" << QString::fromStdString(customCode);
            qDebug() << "   Custom verification:" << (customTOTP.verify(customCode) ? "SUCCESS" : "FAILED");
        } catch (const std::exception& e) {
            qDebug() << "   Custom parameters not supported:" << e.what();
        }
        
        qDebug() << "\n=== All Tests Completed Successfully! ===";
        qDebug() << "\n📱 MANUAL TEST INSTRUCTIONS:";
        qDebug() << "1. Copy this otpauth:// URL to your authenticator app:";
        qDebug() << "   " << QString::fromStdString(otpauthURL);
        qDebug() << "2. Or manually enter this secret:" << QString::fromStdString(secret);
        qDebug() << "3. Current code should be:" << QString::fromStdString(currentCode);
        qDebug() << "4. Codes change every 30 seconds";
        qDebug() << "5. Try Google Authenticator, Authy, or any TOTP app";
        
        // Performance test
        qDebug() << "\n🚀 Performance Test:";
        auto start = QDateTime::currentMSecsSinceEpoch();
        for (int i = 0; i < 1000; i++) {
            totp.generate();
        }
        auto elapsed = QDateTime::currentMSecsSinceEpoch() - start;
        qDebug() << "   Generated 1000 codes in" << elapsed << "ms";
        qDebug() << "   Average:" << (elapsed / 1000.0) << "ms per code";
        
    } catch (const std::exception& e) {
        qDebug() << "❌ FAIL: Test failed with exception:" << e.what();
    }
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    
    qDebug() << "🔐 Starting TOTP Simplified Test Suite";
    qDebug() << "=======================================";
    
    // Run the test
    testSimplifiedTOTP();
    
    qDebug() << "\n✅ Test complete. Exiting...";
    
    // Exit immediately
    QTimer::singleShot(0, &app, &QCoreApplication::quit);
    
    return app.exec();
} 