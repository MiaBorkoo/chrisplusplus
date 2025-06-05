#include <QTest>
#include <QSignalSpy>
#include <memory>
#include "../../models/AccessModel.h"
#include "../../services/files/FileService.h"
#include "../../controllers/AccessController.h"
#include "../../views/AccessDialog.h"
#include "../../network/Client.h"

class TestAccessConnection: public QObject
{
    Q_OBJECT

private:
    // Services
    std::shared_ptr<Client> m_client;
    std::shared_ptr<FileService> m_fileService;
    
    // Model
    std::shared_ptr<AccessModel> m_accessModel;
    
    // View
    AccessDialog* m_accessDialog = nullptr;
    
    // Controller
    AccessController* m_accessController = nullptr;

    // Test state variables
    bool accessGranted = false;
    bool accessRevoked = false;
    bool errorHandled = false;
    QString lastErrorMessage;
    QStringList currentUsers;

private slots:
    void initTestCase() {
        // Create dependencies with dummy values
        m_client = std::make_shared<Client>(QString::fromLatin1("http://dummy-url.com"));
        m_fileService = std::make_shared<FileService>(m_client);
        
        // Initialize model
        m_accessModel = std::make_shared<AccessModel>(m_fileService);
        
        // Initialize view and controller
        const QString testFileName = "test.txt";
        m_accessDialog = new AccessDialog(testFileName, QStringList(), nullptr);
        m_accessController = new AccessController(testFileName, m_accessModel);
        m_accessController->setView(m_accessDialog);

        // Connect signals for testing
        connect(m_accessModel.get(), &AccessModel::accessGranted,
            this, [this](bool success, const QString&, const QString&) { 
                accessGranted = success; 
            });
        
        connect(m_accessModel.get(), &AccessModel::accessRevoked,
            this, [this](bool success, const QString&, const QString&) { 
                accessRevoked = success; 
            });

        connect(m_accessModel.get(), &AccessModel::errorOccurred,
            this, [this](const QString& error) { 
                errorHandled = true;
                lastErrorMessage = error;
            });

        connect(m_accessModel.get(), &AccessModel::usersWithAccessReceived,
            this, [this](const QString&, const QStringList& users) { 
                currentUsers = users;
            });
    }

    void testGrantAccess() {
        // Arrange
        const QString testFile = "test.txt";
        const QString testUser = "testuser@example.com";
        accessGranted = false;

        // Act
        m_accessModel->grantAccess(testFile, testUser);
        
        // Simulate successful grant from service
        m_fileService->accessGranted(true, testFile, testUser);

        // Assert
        QVERIFY(accessGranted);
    }

    void testRevokeAccess() {
        // Arrange
        const QString testFile = "test.txt";
        const QString testUser = "testuser@example.com";
        accessRevoked = false;

        // Act
        m_accessModel->revokeAccess(testFile, testUser);
        
        // Simulate successful revoke from service
        m_fileService->accessRevoked(true, testFile, testUser);

        // Assert
        QVERIFY(accessRevoked);
    }

    void testUserListUpdate() {
        // Arrange
        const QString testFile = "test.txt";
        QStringList testUsers = {"user1@example.com", "user2@example.com"};
        
        // Act
        m_accessModel->getUsersWithAccess(testFile);
        
        // Simulate response from service
        m_fileService->usersWithAccessReceived(testFile, testUsers);

        // Assert
        QCOMPARE(currentUsers, testUsers);
        QCOMPARE(m_accessController->getUsers(), testUsers);
    }

    void testErrorHandling() {
        // Arrange
        errorHandled = false;
        lastErrorMessage.clear();
        const QString errorMsg = "Access denied";

        // Act
        m_fileService->errorOccurred(errorMsg);

        // Assert
        QVERIFY(errorHandled);
        QCOMPARE(lastErrorMessage, errorMsg);
    }

    void testViewUpdates() {
        // Arrange
        const QString testFile = "test.txt";
        const QString testUser = "newuser@example.com";
        QStringList initialUsers = {"user1@example.com"};
        
        // Update the view with initial users
        m_fileService->usersWithAccessReceived(testFile, initialUsers);
        
        // Act - Add new user
        m_accessModel->grantAccess(testFile, testUser);
        m_fileService->accessGranted(true, testFile, testUser);
        
        // Simulate updated user list from service
        QStringList updatedUsers = initialUsers;
        updatedUsers.append(testUser);
        m_fileService->usersWithAccessReceived(testFile, updatedUsers);

        // Assert
        QCOMPARE(m_accessController->getUsers(), updatedUsers);
    }

    void testACLChangedSignal() {
        // Arrange
        const QString testFile = "test.txt";
        const QString testUser = "testuser@example.com";
        QSignalSpy aclSpy(m_accessController, SIGNAL(aclChanged(QString,QStringList)));

        // Act
        m_accessModel->grantAccess(testFile, testUser);
        m_fileService->accessGranted(true, testFile, testUser);
        
        // Simulate updated user list
        QStringList updatedUsers = {testUser};
        m_fileService->usersWithAccessReceived(testFile, updatedUsers);

        // Assert
        QVERIFY(aclSpy.count() > 0);
        QList<QVariant> arguments = aclSpy.takeFirst();
        QCOMPARE(arguments.at(0).toString(), testFile);
        QCOMPARE(arguments.at(1).toStringList(), updatedUsers);
    }

    void cleanupTestCase() {
        delete m_accessDialog;
        delete m_accessController;
    }
};

QTEST_MAIN(TestAccessConnection)
#include "testAccessConnection.moc"
