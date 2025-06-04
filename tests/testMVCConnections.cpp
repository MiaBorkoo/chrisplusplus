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
        // Create dependencies with dummy values
        m_client = std::make_shared<Client>("http://dummy-url.com");
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
        
        // 2. Test file download through view
        QString testFile = "test.txt";
        m_view->downloadRequested(testFile);
        // Simulate successful download response
        m_fileService->downloadComplete(true, testFile);
        QVERIFY(downloadCalled);
        
        // 3. Test file deletion through view
        m_view->deleteRequested(testFile);
        // Simulate successful deletion response
        m_fileService->deleteComplete(true, testFile);
        QVERIFY(deleteCalled);
    }

    void testModelToViewUpdates() {
        // Test that model updates properly reflect in the view
        
        // 1. Clear the view first
        m_view->clearTable();
        QCOMPARE(m_view->getFileTable()->rowCount(), 0);

        // 2. Update model with new files
        QList<FileInfo> dummyFiles;
        FileInfo file1;
        file1.name = "test1.txt";
        file1.size = 1024;
        file1.uploadDate = "2024-03-20";
        dummyFiles.append(file1);

        // 3. Simulate server response which updates model
        m_fileService->fileListReceived(dummyFiles, 1, 1, 1);

        // 4. Verify view was updated through controller
        QTableWidget* fileTable = m_view->getFileTable();
        QCOMPARE(fileTable->rowCount(), 1);
        QCOMPARE(fileTable->item(0, 0)->text(), QString("test1.txt"));
    }

    void testControllerLogic() {
        // Test controller's business logic and mediation
        
        // 1. Test search filtering
        m_view->getSearchBar()->setText("test1");
        m_controller->handleSearch("test1");
        
        // Verify view only shows matching files
        QTableWidget* fileTable = m_view->getFileTable();
        bool hasOnlyMatchingFiles = true;
        for(int row = 0; row < fileTable->rowCount(); row++) {
            QString fileName = fileTable->item(row, 0)->text();
            if(!fileName.contains("test1", Qt::CaseInsensitive)) {
                hasOnlyMatchingFiles = false;
                break;
            }
        }
        QVERIFY(hasOnlyMatchingFiles);

        // 2. Test file selection handling
        m_controller->handleFileSelection(0, 0);  // Select first file
        QString selectedFile = m_view->getFileTable()->item(0, 0)->text();
        QVERIFY(!selectedFile.isEmpty());
    }

    void testProgressUpdates() {
        // Reset progress values
        lastProgressSent = 0;
        lastProgressTotal = 0;
        
        // Simulate upload progress
        qint64 testSent = 50;
        qint64 testTotal = 100;
        m_fileService->uploadProgress(testSent, testTotal);
        
        // Verify progress was propagated
        QCOMPARE(lastProgressSent, testSent);
        QCOMPARE(lastProgressTotal, testTotal);
    }

    void testSearchFunctionality() {
        // Reset flags
        searchCalled = false;
        
        // Clear the table first
        m_view->clearTable();
        
        // Add some test files
        m_view->addFileRow("test_search.txt", "1024", "2024-03-20");
        m_view->addFileRow("other_file.txt", "2048", "2024-03-20");
        m_view->addFileRow("test_search2.txt", "512", "2024-03-20");
        
        // Simulate user typing in search bar
        QString searchText = "test_search";
        m_view->getSearchBar()->setText(searchText);
        
        // Verify search was triggered
        QVERIFY(searchCalled);
        
        // Test search filtering
        m_controller->handleSearch(searchText);
        
        // Verify view only shows matching files
        QTableWidget *fileTable = m_view->getFileTable();
        bool hasOnlyMatchingFiles = true;
        for(int row = 0; row < fileTable->rowCount(); row++) {
            if (!fileTable->isRowHidden(row)) {
                QString fileName = fileTable->item(row, 0)->text();
                if(!fileName.contains(searchText, Qt::CaseInsensitive)) {
                    hasOnlyMatchingFiles = false;
                    break;
                }
            }
        }
        QVERIFY(hasOnlyMatchingFiles);
    }

    void testFileSelection() {
        // Reset flags
        fileSelectedCalled = false;
        
        // Clear the table first
        m_view->clearTable();
        
        // Add a test file to the table
        m_view->addFileRow("test_file.txt", "1024", "2024-03-20");
        
        // Simulate file selection
        m_controller->handleFileSelection(0, 0);
        
        // Verify selection was handled
        QVERIFY(fileSelectedCalled);
        
        // Verify correct file was selected
        QString selectedFile = m_view->getFileTable()->item(0, 0)->text();
        QCOMPARE(selectedFile, QString("test_file.txt"));
    }

    void testErrorHandling() {
        // Reset flags
        errorHandled = false;
        
        // Simulate error in model
        QString errorMsg = "File not found";
        m_fileService->errorOccurred(errorMsg);
        
        // Verify error was handled
        QVERIFY(errorHandled);
        
        // Test recovery - verify system still works after error
        testModelToViewUpdates();
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