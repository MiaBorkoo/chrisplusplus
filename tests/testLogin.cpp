#include <QTest>
#include <QSignalSpy>
#include "../services/auth/AuthService.h"
#include "../network/Client.h"

class TestLogin : public QObject {
    Q_OBJECT

private:
    std::unique_ptr<Client> m_client;
    std::unique_ptr<AuthService> m_authService;

private slots:
    void initTestCase() {
        // Initialize client with local test server URL
        m_client = std::make_unique<Client>("http://localhost:8000", "", this);
        m_authService = std::make_unique<AuthService>(m_client.get(), this);
    }

    void testSuccessfulLogin() {
        // Set up signal spy to monitor login completion signal
        QSignalSpy loginSpy(m_authService.get(), &AuthService::loginCompleted);
        QSignalSpy errorSpy(m_authService.get(), &AuthService::errorOccurred);

        // Attempt login
        m_authService->login("testuser", "hashedpassword123456789012345678901234567890");

        // Wait for response (timeout after 5 seconds)
        QVERIFY(loginSpy.wait(5000));

        // Verify login success
        QCOMPARE(loginSpy.count(), 1);
        QCOMPARE(errorSpy.count(), 0);

        // Check the login response
        QList<QVariant> arguments = loginSpy.takeFirst();
        QVERIFY(arguments.at(0).toBool()); // success should be true
        QVERIFY(!arguments.at(1).toString().isEmpty()); // token should not be empty
    }

    void testFailedLogin() {
        QSignalSpy loginSpy(m_authService.get(), &AuthService::loginCompleted);
        QSignalSpy errorSpy(m_authService.get(), &AuthService::errorOccurred);

        // Attempt login with invalid credentials
        m_authService->login("testuser", "invalidAuthKey");

        // Wait for response
        QVERIFY(loginSpy.wait(5000));

        // Verify login failure
        QCOMPARE(loginSpy.count(), 1);
        QCOMPARE(errorSpy.count(), 1);

        // Check the login response
        QList<QVariant> arguments = loginSpy.takeFirst();
        QVERIFY(!arguments.at(0).toBool()); // success should be false
        QVERIFY(arguments.at(1).toString().isEmpty()); // token should be empty

        // Verify error message
        QString errorMessage = errorSpy.takeFirst().at(0).toString();
        QVERIFY(!errorMessage.isEmpty());
    }

    void testNetworkError() {
        QSignalSpy errorSpy(m_authService.get(), &AuthService::errorOccurred);

        // Set invalid server URL to trigger network error
        m_client = std::make_unique<Client>("https://invalid-server.example", "", this);
        m_authService = std::make_unique<AuthService>(m_client.get(), this);

        // Attempt login
        m_authService->login("testuser", "testpass");

        // Wait for error
        QVERIFY(errorSpy.wait(5000));

        // Verify error occurred
        QCOMPARE(errorSpy.count(), 1);
        QString errorMessage = errorSpy.takeFirst().at(0).toString();
        QVERIFY(!errorMessage.isEmpty());
    }

    void cleanupTestCase() {
        m_authService.reset();
        m_client.reset();
    }
};

#include "testLogin.moc"