#include <QTest>
#include <QSignalSpy>
#include <QLineEdit>
#include <QPushButton>
#include <memory>
#include "../../models/LoginModel.h"
#include "../../services/auth/AuthService.h"
#include "../../controllers/LoginController.h"
#include "../../views/LoginView.h"
#include "../../network/Client.h"

class TestLoginConnection: public QObject
{
    Q_OBJECT

private:
    // Services
    std::shared_ptr<Client> m_client;
    std::shared_ptr<AuthService> m_authService;
    
    // Model
    std::shared_ptr<LoginModel> m_loginModel;
    
    // View
    LoginView* m_loginView = nullptr;
    
    // Controller
    LoginController* m_loginController = nullptr;

private slots:
    void initTestCase() {
        // Create dependencies with dummy values
        m_client = std::make_shared<Client>(QString::fromLatin1("http://dummy-url.com"));
        m_authService = std::make_shared<AuthService>(m_client);
        
        // Initialize model
        m_loginModel = std::make_shared<LoginModel>(m_authService);
        
        // Initialize view
        m_loginView = new LoginView();
        
        // Initialize controller
        m_loginController = new LoginController(m_loginModel);
        m_loginController->setView(m_loginView);
    }

    void testLoginAttempt() {
        // Arrange
        QSignalSpy loginSpy(m_loginView, SIGNAL(loginAttempted(QString,QString)));
        const QString testUsername = "testuser";
        const QString testPassword = "testpass123";

        // Act
        m_loginView->findChild<QLineEdit*>("usernameEdit")->setText(testUsername);
        m_loginView->findChild<QLineEdit*>("passwordEdit")->setText(testPassword);
        QTest::mouseClick(static_cast<QWidget*>(m_loginView->findChild<QPushButton*>("loginButton")), Qt::LeftButton);

        // Assert
        QCOMPARE(loginSpy.count(), 1);
        QList<QVariant> arguments = loginSpy.takeFirst();
        QCOMPARE(arguments.at(0).toString(), testUsername);
        QCOMPARE(arguments.at(1).toString(), testPassword);
        QVERIFY(m_loginView->findChild<QLineEdit*>("usernameEdit")->text().isEmpty());
        QVERIFY(m_loginView->findChild<QLineEdit*>("passwordEdit")->text().isEmpty());
    }

    void testLoginEmptyCredentials() {
        // Arrange
        QSignalSpy loginSpy(m_loginView, SIGNAL(loginAttempted(QString,QString)));

        // Act
        QTest::mouseClick(static_cast<QWidget*>(m_loginView->findChild<QPushButton*>("loginButton")), Qt::LeftButton);

        // Assert
        QCOMPARE(loginSpy.count(), 1);
        QList<QVariant> arguments = loginSpy.takeFirst();
        QVERIFY(arguments.at(0).toString().isEmpty());
        QVERIFY(arguments.at(1).toString().isEmpty());
    }

    void cleanupTestCase() {
        delete m_loginView;
        delete m_loginController;
    }
};

QTEST_MAIN(TestLoginConnection)
#include "testLoginConnection.moc"
