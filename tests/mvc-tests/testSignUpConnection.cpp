#include <QTest>
#include <QSignalSpy>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <memory>
#include "../../models/SignUpModel.h"
#include "../../services/auth/AuthService.h"
#include "../../controllers/SignUpController.h"
#include "../../views/SignUpView.h"
#include "../../network/Client.h"

class TestSignUpConnection: public QObject
{
    Q_OBJECT

private:
    // Services
    std::shared_ptr<Client> m_client;
    std::shared_ptr<AuthService> m_authService;
    
    // Model
    std::shared_ptr<SignUpModel> m_signUpModel;
    
    // View
    SignUpView* m_signUpView = nullptr;
    
    // Controller
    SignUpController* m_signUpController = nullptr;

    // Test state variables
    bool registrationSuccessful = false;
    bool registrationErrorOccurred = false;
    QString lastErrorMessage;

private slots:
    void initTestCase() {
        // Create dependencies with dummy values
        m_client = std::make_shared<Client>(QString::fromLatin1("http://dummy-url.com"));
        m_authService = std::make_shared<AuthService>(m_client);
        
        // Initialize model
        m_signUpModel = std::make_shared<SignUpModel>(m_authService);
        
        // Initialize view
        m_signUpView = new SignUpView();
        
        // Initialize controller
        m_signUpController = new SignUpController(m_signUpView, m_signUpModel);

        // Connect signals for testing
        connect(m_signUpModel.get(), &SignUpModel::registrationSuccess,
            this, [this]() { registrationSuccessful = true; });
        
        connect(m_signUpModel.get(), &SignUpModel::registrationError,
            this, [this](const QString& error) { 
                registrationErrorOccurred = true;
                lastErrorMessage = error;
            });
    }

    void testSignUpAttempt() {
        // Arrange
        QSignalSpy signUpSpy(m_signUpView, SIGNAL(signUpRequested(QString,QString,QString)));
        const QString testUsername = "testuser";
        const QString testPassword = "TestPass123!";
        const QString testConfirmPassword = "TestPass123!";

        // Act
        m_signUpView->findChild<QLineEdit*>("usernameEdit")->setText(testUsername);
        m_signUpView->findChild<QLineEdit*>("passwordEdit")->setText(testPassword);
        m_signUpView->findChild<QLineEdit*>("confirmPasswordEdit")->setText(testConfirmPassword);
        QTest::mouseClick(static_cast<QWidget*>(m_signUpView->findChild<QPushButton*>("signUpButton")), Qt::LeftButton);

        // Assert
        QCOMPARE(signUpSpy.count(), 1);
        QList<QVariant> arguments = signUpSpy.takeFirst();
        QCOMPARE(arguments.at(0).toString(), testUsername);
        QCOMPARE(arguments.at(1).toString(), testPassword);
        QCOMPARE(arguments.at(2).toString(), testConfirmPassword);
        QVERIFY(m_signUpView->findChild<QLineEdit*>("usernameEdit")->text().isEmpty());
        QVERIFY(m_signUpView->findChild<QLineEdit*>("passwordEdit")->text().isEmpty());
        QVERIFY(m_signUpView->findChild<QLineEdit*>("confirmPasswordEdit")->text().isEmpty());
    }

    void testPasswordMismatch() {
        // Arrange
        QSignalSpy signUpSpy(m_signUpView, SIGNAL(signUpRequested(QString,QString,QString)));
        const QString testUsername = "testuser";
        const QString testPassword = "TestPass123!";
        const QString testConfirmPassword = "DifferentPass123!";

        // Act
        m_signUpView->findChild<QLineEdit*>("usernameEdit")->setText(testUsername);
        m_signUpView->findChild<QLineEdit*>("passwordEdit")->setText(testPassword);
        m_signUpView->findChild<QLineEdit*>("confirmPasswordEdit")->setText(testConfirmPassword);
        QTest::mouseClick(static_cast<QWidget*>(m_signUpView->findChild<QPushButton*>("signUpButton")), Qt::LeftButton);

        // Assert
        QCOMPARE(signUpSpy.count(), 1);
        QList<QVariant> arguments = signUpSpy.takeFirst();
        QCOMPARE(arguments.at(0).toString(), testUsername);
        QCOMPARE(arguments.at(1).toString(), testPassword);
        QCOMPARE(arguments.at(2).toString(), testConfirmPassword);
        
        // Verify error handling
        QVERIFY(registrationErrorOccurred);
        QVERIFY(lastErrorMessage.contains("Passwords do not match", Qt::CaseInsensitive));
    }

    void testInvalidUsername() {
        // Arrange
        const QString testUsername = "u"; // Too short username
        const QString testPassword = "TestPass123!";
        const QString testConfirmPassword = "TestPass123!";

        // Act
        m_signUpModel->registerUser(testUsername, testPassword, testConfirmPassword);

        // Assert
        QVERIFY(registrationErrorOccurred);
        QVERIFY(lastErrorMessage.contains("Username", Qt::CaseInsensitive));
    }

    void testInvalidPassword() {
        // Arrange
        const QString testUsername = "validuser";
        const QString testPassword = "weak"; // Too weak password
        const QString testConfirmPassword = "weak";

        // Act
        m_signUpModel->registerUser(testUsername, testPassword, testConfirmPassword);

        // Assert
        QVERIFY(registrationErrorOccurred);
        QVERIFY(lastErrorMessage.contains("Password", Qt::CaseInsensitive));
    }

    void testSuccessfulRegistration() {
        // Arrange
        const QString testUsername = "validuser";
        const QString testPassword = "ValidPass123!";
        const QString testConfirmPassword = "ValidPass123!";

        // Reset test flags
        registrationSuccessful = false;
        registrationErrorOccurred = false;
        lastErrorMessage.clear();

        // Act
        m_signUpModel->registerUser(testUsername, testPassword, testConfirmPassword);
        
        // Simulate successful registration response from service
        m_authService->registrationCompleted(true);

        // Assert
        QVERIFY(registrationSuccessful);
        QVERIFY(!registrationErrorOccurred);
    }

    void testNavigationToLogin() {
        // Arrange
        QSignalSpy loginSpy(m_signUpView, SIGNAL(loginRequested()));

        // Act - simulate clicking the login link
        QLabel* loginLink = m_signUpView->findChild<QLabel*>("loginLink");
        QVERIFY(loginLink != nullptr);
        QTest::mouseClick(loginLink, Qt::LeftButton);

        // Assert
        QCOMPARE(loginSpy.count(), 1);
    }

    void cleanupTestCase() {
        delete m_signUpView;
        delete m_signUpController;
    }
};

QTEST_MAIN(TestSignUpConnection)
#include "testSignUpConnection.moc"
