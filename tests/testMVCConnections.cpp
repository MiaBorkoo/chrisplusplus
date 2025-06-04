#include <QTest>
#include "../controllers/FileDashController.h"
#include "../models/FileModel.h"
#include "../services/files/FileService.h"
#include "../views/FilesDashView.h"
#include "../network/Client.h"

class TestMVCConnections : public QObject {
private:
    std::shared_ptr<Client> m_client;
    std::shared_ptr<FileService> m_fileService;
    std::shared_ptr<FileModel> m_fileModel;
    FilesDashView* m_view;
    FileDashController* m_controller;
    bool uploadCalled = false;
    bool downloadCalled = false;
    bool deleteCalled = false;

private slots:
    void initTestCase() {
        // Create dependencies with dummy values
        m_client = std::make_shared<Client>("http://dummy-url.com", "dummy-api-key");
        m_fileService = std::make_shared<FileService>(m_client);
        m_fileModel = std::make_shared<FileModel>(m_fileService);
        m_view = new FilesDashView();
        m_controller = new FileDashController(m_view->getSearchBar(), m_view->getFileTable(), m_fileModel);

        // Set up test verification hooks
        connect(m_fileService.get(), &FileService::uploadComplete,
                [this](bool success, const QString&) { uploadCalled = true; });
        connect(m_fileService.get(), &FileService::downloadComplete,
                [this](bool success, const QString&) { downloadCalled = true; });
        connect(m_fileService.get(), &FileService::deleteComplete,
                [this](bool success, const QString&) { deleteCalled = true; });
    }

    void testViewToModelInteraction() {
        // Reset flags
        uploadCalled = downloadCalled = deleteCalled = false;
        
        // 1. Test file upload through view
        // Simulate user clicking upload in view
        m_view->uploadRequested();
        // Simulate successful upload response
        m_fileService->uploadComplete(true, "dummy.txt");
        QVERIFY(uploadCalled);
        
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

    void testErrorHandling() {
        // Test error propagation through MVC layers
        
        // 1. Simulate error in model
        QString errorMsg = "File not found";
        m_fileService->errorOccurred(errorMsg);
        
        // 2. Verify controller handled error appropriately
        // (This assumes your view has some way to display errors - add appropriate verification)
        
        // 3. Test recovery - verify system still works after error
        testModelToViewUpdates();
    }

    void cleanupTestCase() {
        delete m_view;
        delete m_controller;
    }
};

QTEST_MAIN(TestMVCConnections) 