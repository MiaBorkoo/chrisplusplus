#include <QTest>
#include <QSignalSpy>
#include "../models/FileModel.h"
#include "../models/LoginModel.h"
#include "../services/files/FileService.h"
#include "../services/auth/AuthService.h"
#include "../controllers/FileDashController.h"
#include "../controllers/LoginController.h"
#include "../views/LoginView.h"
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
    QLineEdit* m_searchBar;
    QTableWidget* m_fileTable;
    
    // Controllers
    LoginController* m_loginController;
    FileDashController* m_fileDashController;

    // Test state tracking
    bool uploadCalled = false;
    bool downloadCalled = false;
    bool deleteCalled = false;
    bool searchCalled = false;
    bool fileSelectedCalled = false;
    bool errorHandled = false;
    bool loginSucceeded = false;
    bool loginFailed = false;
    QString lastErrorMessage;
    qint64 lastProgressSent = 0;
    qint64 lastProgressTotal = 0;

private slots:
    // Setup and teardown
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
        m_searchBar = new QLineEdit();
        m_fileTable = new QTableWidget();
        
        // Initialize controllers
        m_loginController = new LoginController(m_loginModel);
        m_loginController->setView(m_loginView);
        
        m_fileDashController = new FileDashController(m_searchBar, m_fileTable, m_fileModel);

        // Connect file model signals
        connect(m_fileModel.get(), &FileModel::fileUploaded,
                this, [this](bool success, const QString&) { uploadCalled = success; });
        connect(m_fileModel.get(), &FileModel::fileDownloaded,
                this, [this](bool success, const QString&) { downloadCalled = success; });
        connect(m_fileModel.get(), &FileModel::fileDeleted,
                this, [this](bool success, const QString&) { deleteCalled = success; });
        connect(m_fileModel.get(), &FileModel::uploadProgress,
                this, [this](qint64 sent, qint64 total) { 
                    lastProgressSent = sent;
                    lastProgressTotal = total;
                });

        // Connect login model signals
        connect(m_loginModel.get(), &LoginModel::loginSuccess,
                this, [this]() { loginSucceeded = true; });
        connect(m_loginModel.get(), &LoginModel::loginError,
                this, [this](const QString& error) { 
                    loginFailed = true;
                    lastErrorMessage = error;
                });
    }

    void cleanup() {
        // Reset test state flags
        uploadCalled = false;
        downloadCalled = false;
        deleteCalled = false;
        searchCalled = false;
        fileSelectedCalled = false;
        errorHandled = false;
        loginSucceeded = false;
        loginFailed = false;
        lastErrorMessage.clear();
        lastProgressSent = 0;
        lastProgressTotal = 0;
    }

    void cleanupTestCase() {
        delete m_loginView;
        delete m_searchBar;
        delete m_fileTable;
        delete m_loginController;
        delete m_fileDashController;
    }

    // Login functionality tests
    void testLoginSuccess() {
        // Arrange
        const QString testUsername = "testuser";
        const QString testPassword = "testpass123";

        // Act
        m_loginView->findChild<QLineEdit*>("usernameEdit")->setText(testUsername);
        m_loginView->findChild<QLineEdit*>("passwordEdit")->setText(testPassword);
        QTest::mouseClick(m_loginView->findChild<QPushButton*>("loginButton"), Qt::LeftButton);

        // Assert
        QVERIFY(loginSucceeded);
        QVERIFY(!loginFailed);
        QVERIFY(m_loginView->findChild<QLineEdit*>("usernameEdit")->text().isEmpty());
        QVERIFY(m_loginView->findChild<QLineEdit*>("passwordEdit")->text().isEmpty());
    }

    void testLoginFailure() {
        // Arrange
        const QString testUsername = "wronguser";
        const QString testPassword = "wrongpass";

        // Act
        m_loginView->findChild<QLineEdit*>("usernameEdit")->setText(testUsername);
        m_loginView->findChild<QLineEdit*>("passwordEdit")->setText(testPassword);
        QTest::mouseClick(m_loginView->findChild<QPushButton*>("loginButton"), Qt::LeftButton);

        // Assert
        QVERIFY(!loginSucceeded);
        QVERIFY(loginFailed);
        QVERIFY(!lastErrorMessage.isEmpty());
    }

    void testLoginEmptyCredentials() {
        // Act
        QTest::mouseClick(m_loginView->findChild<QPushButton*>("loginButton"), Qt::LeftButton);

        // Assert
        QVERIFY(!loginSucceeded);
        QVERIFY(loginFailed);
        QVERIFY(lastErrorMessage.contains("empty", Qt::CaseInsensitive));
    }

    // File operations tests
    void testFileUpload() {
        // Arrange
        const QString testFile = "test.txt";
        
        // Act
        m_fileModel->uploadFile(testFile);
        
        // Assert
        QVERIFY(uploadCalled);
        QVERIFY(lastProgressSent <= lastProgressTotal);
    }

    void testFileDownload() {
        // Arrange
        const QString testFile = "test.txt";
        const QString savePath = "/tmp/test.txt";
        
        // Act
        m_fileModel->downloadFile(testFile, savePath);
        
        // Assert
        QVERIFY(downloadCalled);
    }

    void testFileDelete() {
        // Arrange
        const QString testFile = "test.txt";
        
        // Act
        m_fileModel->deleteFile(testFile);
        
        // Assert
        QVERIFY(deleteCalled);
    }

    // Search functionality tests
    void testSearch() {
        // Arrange
        QSignalSpy searchSpy(m_fileDashController, SIGNAL(searchRequested(QString)));
        const QString searchText = "test";
        
        // Act
        m_searchBar->setText(searchText);
        QTest::keyClick(m_searchBar, Qt::Key_Return);
        
        // Assert
        QCOMPARE(searchSpy.count(), 1);
        QCOMPARE(searchSpy.first().first().toString(), searchText);
    }

    // Progress update tests
    void testProgressUpdates() {
        // Arrange
        const QString testFile = "large_test.txt";
        const qint64 expectedTotal = 1000;
        
        // Act
        m_fileModel->uploadFile(testFile);
        
        // Assert
        QVERIFY(lastProgressTotal > 0);
        QVERIFY(lastProgressSent <= lastProgressTotal);
    }

    // Error handling tests
    void testErrorHandling() {
        // Arrange
        const QString testFile = "nonexistent.txt";
        
        // Act
        m_fileModel->downloadFile(testFile, "/tmp/nonexistent.txt");
        
        // Assert
        QVERIFY(loginFailed || !downloadCalled);
        QVERIFY(!lastErrorMessage.isEmpty());
    }
};

QTEST_MAIN(TestMVCConnections)
#include "testMVCConnections.moc"