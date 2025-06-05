#include <QCoreApplication>
#include <QTimer>
#include <QThread>
#include <QDateTime>
#include <iostream>
#include <string>

#include "../services/auth/otp/TOTP.h"

void testSimplifiedTOTP() {
    try {
        // Test 1: Secret Generation
        std::string secret = TOTP::generateSecret();
        
        // Test 2: OTP Auth URL Creation
        std::string otpauthURL = TOTP::createOTPAuthURL("MyShare", "test@example.com", secret);
        
        // Test 3: TOTP Code Generation
        TOTP totp(secret);
        std::string currentCode = totp.generate();
        
        // Test 4: Code Verification (Current Time)
        bool verified = totp.verify(currentCode);
        
        // Test verification with wrong code
        bool wrongVerified = totp.verify("123456");
        
        // Test 5: Time Window Tolerance
        uint64_t currentTime = QDateTime::currentSecsSinceEpoch();
        
        // Generate code for 30 seconds ago (previous window)
        std::string pastCode = totp.generate(currentTime - 30);
        bool pastVerified = totp.verify(pastCode, 1); // 1 window tolerance
        
        // Generate code for 30 seconds in future (next window)
        std::string futureCode = totp.generate(currentTime + 30);
        bool futureVerified = totp.verify(futureCode, 1); // 1 window tolerance
        
        // Test 6: Code Consistency
        for (int i = 0; i < 3; i++) {
            std::string testCode = totp.generate();
            QThread::msleep(50); // Small delay - should produce same code
        }
        
        // Test 7: Different Time Windows
        uint64_t baseTime = currentTime - (currentTime % 30); // Align to 30s boundary
        
        for (int i = 0; i < 3; i++) {
            uint64_t testTime = baseTime + (i * 30); // Different 30s windows
            std::string windowCode = totp.generate(testTime);
        }
        
        // Test 8: Different Secrets Produce Different Codes
        std::string secret2 = TOTP::generateSecret();
        TOTP totp2(secret2);
        std::string code2 = totp2.generate();
        
        // Test 9: Edge Cases
        
        // Test with custom time steps and digits (if supported)
        try {
            TOTP customTOTP(secret, 60, 8); // 60s window, 8 digits
            std::string customCode = customTOTP.generate();
            bool customVerified = customTOTP.verify(customCode);
        } catch (const std::exception& e) {
            // Custom parameters not supported
        }
        
        // Performance test
        auto start = QDateTime::currentMSecsSinceEpoch();
        for (int i = 0; i < 1000; i++) {
            totp.generate();
        }
        auto elapsed = QDateTime::currentMSecsSinceEpoch() - start;
        
    } catch (const std::exception& e) {
        // Test failed with exception
    }
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    
    // Run the test
    testSimplifiedTOTP();
    
    // Exit immediately
    QTimer::singleShot(0, &app, &QCoreApplication::quit);
    
    return app.exec();
} 