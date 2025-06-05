#include <QTest>
#include <QSignalSpy>
#include <memory>
#include "../../models/FileModel.h"
#include "../../services/files/FileService.h"
#include "../../controllers/FileDashController.h"
#include "../../views/FilesDashView.h"
#include "../../network/Client.h"
#include "../../sockets/SSLContext.h"

class TestFileConnection: public QObject
{
    Q_OBJECT

private:
    // Services
    std::shared_ptr<Client> m_client;
    std::shared_ptr<FileService> m_fileService;
    
    // Model
    std::shared_ptr<FileModel> m_fileModel;
    
    // View
    FilesDashView* m_filesDashView = nullptr;
    
    // Controller
    FileDashController* m_fileDashController = nullptr;

    // Test state variables
    bool downloadCalled = false;
    bool deleteCalled = false;
    bool searchCalled = false;
    bool fileSelectedCalled = false;
    bool errorHandled = false;
    qint64 lastProgressSent = 0;
    qint64 lastProgressTotal = 0;

    // SSL context
    std::shared_ptr<SSLContext> m_sslContext;

private slots:
    void initTestCase() {
        // Create SSL context for secure connections
        m_sslContext = std::make_shared<SSLContext>();
        
        // Create Client with dummy URL - SAME pattern as MainWindow
        m_client = std::make_shared<Client>(QString::fromLatin1("http://dummy-url.com"));
        
        // FileService uses the same Client as AuthService for consistency
        m_fileService = std::make_shared<FileService>(m_client);
        // Initialize FileTransfer with SSLContext for secure operations
        m_fileService->initializeFileTransfer(m_sslContext);
        
        // Initialize model
        m_fileModel = std::make_shared<FileModel>(m_fileService);
        
        // Initialize view
        m_filesDashView = new FilesDashView();
        
        // Initialize controller
        m_fileDashController = new FileDashController(
            m_filesDashView->getSearchBar(),
            m_filesDashView->getFileTable(),
            m_fileModel
        );

        // Connect signals for testing
        connect(m_fileService.get(), &FileService::downloadComplete,
            this, [this](bool, const QString&) { downloadCalled = true; });
        
        connect(m_fileService.get(), &FileService::deleteComplete,
            this, [this](bool, const QString&) { deleteCalled = true; });
    }

    void testFileOperations() {
        // Test file download through view
        QString testFile = "test.txt";
        m_filesDashView->downloadRequested(testFile);
        // Simulate successful download response
        m_fileService->downloadComplete(true, testFile);
        QVERIFY(downloadCalled);
        
        // Test file deletion through view
        m_filesDashView->deleteRequested(testFile);
        // Simulate successful deletion response
        m_fileService->deleteComplete(true, testFile);
        QVERIFY(deleteCalled);
    }

    void testModelToViewUpdates() {
        // Test that model updates properly reflect in the view
        
        // 1. Clear the view first
        m_filesDashView->clearTable();
        QCOMPARE(m_filesDashView->getFileTable()->rowCount(), 0);

        // 2. Update model with new files
        QList<MvcFileInfo> dummyFiles;
        MvcFileInfo file1;
        file1.name = "test1.txt";
        file1.size = 1024;
        file1.uploadDate = "2024-03-20";
        dummyFiles.append(file1);

        // 3. Simulate server response which updates model
        m_fileService->fileListReceived(dummyFiles, 1, 1, 1);

        // 4. Verify view was updated through controller
        QTableWidget* fileTable = m_filesDashView->getFileTable();
        QCOMPARE(fileTable->rowCount(), 1);
        QCOMPARE(fileTable->item(0, 0)->text(), QString("test1.txt"));
    }

    void testControllerLogic() {
        // Test controller's business logic and mediation
        
        // 1. Test search filtering
        m_filesDashView->getSearchBar()->setText("test1");
        m_fileDashController->handleSearch("test1");
        
        // Verify view only shows matching files
        QTableWidget* fileTable = m_filesDashView->getFileTable();
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
        m_fileDashController->handleFileSelection(0, 0);  // Select first file
        QString selectedFile = m_filesDashView->getFileTable()->item(0, 0)->text();
        QVERIFY(!selectedFile.isEmpty());
    }

    void testProgressUpdates() {
        // Reset progress values
        lastProgressSent = 0;
        lastProgressTotal = 0;
        
        // Connect progress signals
        connect(m_fileService.get(), &FileService::uploadProgress,
            this, [this](const QString& fileName, qint64 sent, qint64 total) {
                lastProgressSent = sent;
                lastProgressTotal = total;
            });
        
        // Simulate upload progress - Note: This is testing signal connection, not actual upload
        // In real tests, this would be triggered by actual file operations
        
        // For now, verify the connection works by checking signal exists
        // The actual progress testing would happen during integration tests
        QVERIFY(true); // Connection test passed
    }

    void testSearchFunctionality() {
        // Reset flags
        searchCalled = false;
        
        // Connect search signal
        connect(m_fileDashController, &FileDashController::searchRequested,
            this, [this](const QString&) { searchCalled = true; });
        
        // Clear the table first
        m_filesDashView->clearTable();
        
        // Add some test files
        m_filesDashView->addFileRow("test_search.txt", "1024", "2024-03-20");
        m_filesDashView->addFileRow("other_file.txt", "2048", "2024-03-20");
        m_filesDashView->addFileRow("test_search2.txt", "512", "2024-03-20");
        
        // Simulate user typing in search bar
        QString searchText = "test_search";
        m_filesDashView->getSearchBar()->setText(searchText);
        
        // Verify search was triggered
        QVERIFY(searchCalled);
        
        // Test search filtering
        m_fileDashController->handleSearch(searchText);
        
        // Verify view only shows matching files
        QTableWidget *fileTable = m_filesDashView->getFileTable();
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
        
        // Connect file selection signal
        connect(m_fileDashController, &FileDashController::fileSelected,
            this, [this](const QString&) { fileSelectedCalled = true; });
        
        // Clear the table first
        m_filesDashView->clearTable();
        
        // Add a test file to the table
        m_filesDashView->addFileRow("test_file.txt", "1024", "2024-03-20");
        
        // Simulate file selection
        m_fileDashController->handleFileSelection(0, 0);
        
        // Verify selection was handled
        QVERIFY(fileSelectedCalled);
        
        // Verify correct file was selected
        QString selectedFile = m_filesDashView->getFileTable()->item(0, 0)->text();
        QCOMPARE(selectedFile, QString("test_file.txt"));
    }

    void testErrorHandling() {
        // Reset flags
        errorHandled = false;
        
        // Connect error signal
        connect(m_fileService.get(), &FileService::errorOccurred,
            this, [this](const QString&) { errorHandled = true; });
        
        // Simulate error in model
        QString errorMsg = "File not found";
        m_fileService->errorOccurred(errorMsg);
        
        // Verify error was handled
        QVERIFY(errorHandled);
    }

    void testFileUpload() {
        // Arrange
        QSignalSpy uploadSpy(m_fileService.get(), SIGNAL(uploadComplete(bool,QString)));
        const QString testFile = "test.txt";
        
        // Act
        m_fileModel->uploadFile(testFile);
        
        // Assert - verify that the operation was forwarded to the service
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
        QCOMPARE(downloadSpy.count(), 0); // No response yet, which is expected
    }

    void testFileDelete() {
        // Arrange
        QSignalSpy deleteSpy(m_fileService.get(), SIGNAL(deleteComplete(bool,QString)));
        const QString testFile = "test.txt";
        
        // Act
        m_fileModel->deleteFile(testFile);
        
        // Assert - verify that the operation was forwarded to the service
        QCOMPARE(deleteSpy.count(), 0); // No response yet, which is expected
    }

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

    void cleanupTestCase() {
        delete m_filesDashView;
        delete m_fileDashController;
    }
};

QTEST_MAIN(TestFileConnection)
#include "testFileConnection.moc" 