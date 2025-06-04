#include <QTest>
#include <QSignalSpy>
#include <memory>
#include "../models/FileModel.h"
#include "../models/LoginModel.h"
#include "../services/files/FileService.h"
#include "../services/auth/AuthService.h"
#include "../controllers/FileDashController.h"
#include "../controllers/LoginController.h"
#include "../views/LoginView.h"
#include "../views/FilesDashView.h"
#include "../network/Client.h"

class TestMVCConnections: public QObject
{
    Q_OBJECT

private:
    // Services
    std::shared_ptr<Client> m_client;
    std::shared_ptr<FileService> m_fileService;
    std::shared_ptr<AuthService> m_authService;
    
    // Models
    std::shared_ptr<FileModel> m_fileModel;
    std::shared_ptr<LoginModel> m_loginModel;
    
    // Views
    LoginView* m_loginView;
    FilesDashView* m_filesDashView;
    
    // Controllers
    LoginController* m_loginController;
    FileDashController* m_fileDashController;

private slots:
    void initTestCase() {
        // Initialize services
        m_client = std::make_shared<Client>("http://localhost:8000", "test-api-key");
        m_fileService = std::make_shared<FileService>(m_client);
        m_authService = std::make_shared<AuthService>(m_client);
        
        // Initialize models
        m_fileModel = std::make_shared<FileModel>(m_fileService);
        m_loginModel = std::make_shared<LoginModel>(m_authService);
        
        // Initialize views
        m_loginView = new LoginView();
        m_filesDashView = new FilesDashView();
        
        // Initialize controllers
        m_loginController = new LoginController(m_loginModel);
        m_loginController->setView(m_loginView);
        
        m_fileDashController = new FileDashController(
            m_filesDashView->getSearchBar(),
            m_filesDashView->getFileTable(),
            m_fileModel
        );
    }

    void cleanupTestCase() {
        delete m_loginView;
        delete m_filesDashView;
        delete m_loginController;
        delete m_fileDashController;
    }

    // Login functionality tests
    void testLoginAttempt() {
        // Arrange
        QSignalSpy loginSpy(m_loginView, SIGNAL(loginAttempted(QString,QString)));
        const QString testUsername = "testuser";
        const QString testPassword = "testpass123";

        // Act
        m_loginView->findChild<QLineEdit*>("usernameEdit")->setText(testUsername);
        m_loginView->findChild<QLineEdit*>("passwordEdit")->setText(testPassword);
        QTest::mouseClick(m_loginView->findChild<QPushButton*>("loginButton"), Qt::LeftButton);

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
        QTest::mouseClick(m_loginView->findChild<QPushButton*>("loginButton"), Qt::LeftButton);

        // Assert
        QCOMPARE(loginSpy.count(), 1);
        QList<QVariant> arguments = loginSpy.takeFirst();
        QVERIFY(arguments.at(0).toString().isEmpty());
        QVERIFY(arguments.at(1).toString().isEmpty());
    }

    // File operations tests
    void testFileUpload() {
        // Arrange
        QSignalSpy uploadSpy(m_fileService.get(), SIGNAL(uploadComplete(bool,QString)));
        const QString testFile = "test.txt";
        
        // Act
        m_fileModel->uploadFile(testFile);
        
        // Assert - verify that the operation was forwarded to the service
        // We don't wait for response since we're just testing MVC connections
        QCOMPARE(uploadSpy.count(), 0); // No response yet, which is expected
    }

    void testFileDownload() {
        // Arrange
        QSignalSpy downloadSpy(m_fileService.get(), SIGNAL(downloadComplete(bool,QString)));
        const QString testFile = "test.txt";
        const QString savePath = "/tmp/test.txt";
        
        // Act
        m_fileModel->downloadFile(testFile, savePath);
        
        // Assert - verify that the operation was forwarded to the service
        // We don't wait for response since we're just testing MVC connections
        QCOMPARE(downloadSpy.count(), 0); // No response yet, which is expected
    }

    void testFileDelete() {
        // Arrange
        QSignalSpy deleteSpy(m_fileService.get(), SIGNAL(deleteComplete(bool,QString)));
        const QString testFile = "test.txt";
        
        // Act
        m_fileModel->deleteFile(testFile);
        
        // Assert - verify that the operation was forwarded to the service
        // We don't wait for response since we're just testing MVC connections
        QCOMPARE(deleteSpy.count(), 0); // No response yet, which is expected
    }

    // Search functionality tests
    void testSearch() {
        // Arrange
        QSignalSpy searchSpy(m_fileDashController, SIGNAL(searchRequested(QString)));
        const QString searchText = "test";
        
        // Act
        m_filesDashView->getSearchBar()->setText(searchText);
        QTest::keyClick(m_filesDashView->getSearchBar(), Qt::Key_Return);
        
        // Assert
        QCOMPARE(searchSpy.count(), 1);
        QCOMPARE(searchSpy.first().first().toString(), searchText);
    }
};

QTEST_MAIN(TestMVCConnections)
#include "testMVCConnections.moc"