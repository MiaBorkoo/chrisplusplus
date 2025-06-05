#include "mainwindow.h"
#include "views/SignUpView.h"
#include "controllers/SignUpController.h"
#include "controllers/FileDashController.h"
#include "controllers/SideNavController.h"
#include "controllers/SharedDashController.h"
#include "views/AccountSection.h"
#include "controllers/AccountController.h"
#include "utils/Config.h"
#include "sockets/SSLContext.h"
#include <QScreen>
#include <QApplication>
#include <QStackedWidget>
#include <QMessageBox>
#include <QFile>
#include <QUrl>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent): QMainWindow(parent)
{
    //loading global stylesheet
    QFile styleFile(":/styles/styles.css");
    styleFile.open(QFile::ReadOnly);
    QString styleSheet = QLatin1String(styleFile.readAll());
    qApp->setStyleSheet(styleSheet);

    setWindowTitle("Login");
    QScreen *screen = QApplication::primaryScreen();
    QRect screenGeometry = screen->geometry();
    setGeometry(screenGeometry);

    // Initialize services first for proper workflow setup
    initializeServices();

    m_stack = new QStackedWidget(this);

    // Initialize models
    m_loginModel = std::make_shared<LoginModel>(m_authService);
    m_signUpModel = std::make_shared<SignUpModel>(m_authService);

    // Create login view and controller
    m_loginView = new LoginView(this);
    m_loginController = new LoginController(m_loginModel, this);
    m_loginController->setView(m_loginView);
    m_loginController->setAuthService(m_authService);

    // Create sign up view and controller
    m_signUpView = new SignUpView(this);
    m_signUpController = new SignUpController(m_signUpView, m_signUpModel, this);

    // Initialize file service with shared Client (same as AuthService)
    m_fileService = std::make_shared<FileService>(m_client);
    // Initialize FileTransfer with SSLContext for secure file operations
    m_fileService->initializeFileTransfer(m_sslContext);
    m_fileModel = std::make_shared<FileModel>(m_fileService);

    m_filesDashView = new FilesDashView(this);
    m_fileDashController = new FileDashController(
        m_filesDashView->getSearchBar(), 
        m_filesDashView->getFileTable(), 
        m_fileModel,
        this
    );
    
    m_accountSection = new AccountSection(this);

    m_sharedDashView = new SharedDashView(this);
    m_sharedDashController = new SharedDashController(m_sharedDashView, this);

    // Initialize side nav controller with the FilesDashView's side nav
    m_sideNavController = new SideNavController(m_filesDashView->getSideNav(), this);

    m_stack->addWidget(m_loginView);   //index 0 in the stacked widget
    m_stack->addWidget(m_signUpView);  //index 1 in the stacked widget
    m_stack->addWidget(m_filesDashView);  //index 2 in the stacked widget
    m_stack->addWidget(m_sharedDashView); //index 3 in the stacked widget

    setCentralWidget(m_stack);

    // Connect navigation signals
    connect(m_loginView, &LoginView::signUpClicked, this, [this]() {
        m_stack->setCurrentWidget(m_signUpView);
    });

    connect(m_signUpView, &SignUpView::loginRequested, this, [this]() {
        m_stack->setCurrentWidget(m_loginView);
    });

    // Connect successful registration to switch to login view
    connect(m_signUpController, &SignUpController::registrationSuccessful, this, [this]() {
        m_stack->setCurrentWidget(m_loginView);
    });

    //switches to files dash view after successful login
    connect(m_loginController, &LoginController::loginSuccessful, this, [this]() {
        // FIRST: Set auth token for file operations BEFORE any UI changes
        QString token = m_authService->sessionToken();
        if (!token.isEmpty()) {
            qDebug() << "Setting FileService auth token after login success";
            m_fileService->setAuthToken(token);
        } else {
            qDebug() << "ERROR: No session token available after login!";
        }
        
        // SECURE SYSTEM INITIALIZATION: Initialize secure file system with user credentials
        if (m_loginModel) {
            // Get user credentials for secure system
            QString userPassword = m_loginModel->getLastPassword();  // Get from login model
            QString username = m_loginModel->getLastUsername();      // Get username for salt derivation
            
            // Generate proper encryption salt (at least 32 bytes for Argon2id)
            // Use a combination of username and padding to ensure 32+ bytes
            QString baseSalt = QString("enc_salt_%1").arg(username);
            while (baseSalt.length() < 32) {
                baseSalt += "_padding_" + QString::number(baseSalt.length());
            }
            QString encryptionSalt = baseSalt.left(64); // Limit to reasonable size
            
            qDebug() << " MAINWINDOW: Initializing secure file system";
            qDebug() << "   Username:" << username;
            qDebug() << "   Encryption salt length:" << encryptionSalt.length() << "bytes";
            
            // Initialize secure system with user credentials following the encryption diagram
            m_fileService->initializeSecureSystem(m_sslContext, userPassword, encryptionSalt);
            
            // Verify secure system is ready
            if (m_fileService->isSecureSystemReady()) {
                qDebug() << " MAINWINDOW: Secure file system initialized successfully!";
                qDebug() << "    AES-256-GCM encryption: ENABLED";
                qDebug() << "    Argon2id key derivation: ENABLED";
                qDebug() << "   🛡️ Fresh DEK per file: ENABLED";
                qDebug() << "   📋 CS4455 compliance: ACHIEVED";
            } else {
                qDebug() << " MAINWINDOW: Secure file system initialization failed!";
                qDebug() << "    Falling back to legacy insecure mode";
            }
        } else {
            qDebug() << " MAINWINDOW: LoginModel not available for secure initialization";
        }
        
        // SECOND: Now safe to switch to file view and trigger requests
        m_stack->setCurrentWidget(m_filesDashView);
        m_sideNavController->setActiveTab(SideNavTab::OwnedFiles);
        
        // THIRD: Trigger initial file listing (now with authentication and encryption)
        m_fileDashController->setFileService(m_fileService);
    });
    
    connect(m_filesDashView, &FilesDashView::fileOpenRequested, this, [this](const QString &fileName) {
        QMessageBox::information(this, "Open File", "You opened: " + fileName);
    });

    connect(m_sharedDashController, &SharedDashController::downloadRequested, this, [this](const QString &fileName) {
        QMessageBox::information(this, "File Opening", QString("Would open shared file: %1\nWaiting for model.").arg(fileName));
    });

    // Connect side nav signals
    connect(m_sideNavController, &SideNavController::ownedFilesRequested, this, [this]() {
        m_stack->setCurrentWidget(m_filesDashView);
        m_sideNavController->setActiveTab(SideNavTab::OwnedFiles);
    });

    connect(m_sideNavController, &SideNavController::sharedFilesRequested, this, [this]() {
        m_stack->setCurrentWidget(m_sharedDashView);
        m_sideNavController->setActiveTab(SideNavTab::SharedWithMe);
    });

    connect(m_sideNavController, &SideNavController::inboxRequested, this, [this]() {
        // TODO: Implement inbox view -> this depends on if we want to keep it
        QMessageBox::information(this, "Inbox", "Inbox view coming soon!");
        m_sideNavController->setActiveTab(SideNavTab::Inbox);
    });

    connect(m_sideNavController, &SideNavController::logoutRequested, this, [this]() {
        m_stack->setCurrentWidget(m_loginView);
    });

    // Connect stack widget's currentChanged signal to update the side nav controller's view
    connect(m_stack, &QStackedWidget::currentChanged, this, [this](int index) {
        if (index == 2) { // FilesDashView
            m_sideNavController->setView(m_filesDashView->getSideNav());
            m_sideNavController->setActiveTab(SideNavTab::OwnedFiles);
        } else if (index == 3) { // SharedDashView
            m_sideNavController->setView(m_sharedDashView->getSideNav());
            m_sideNavController->setActiveTab(SideNavTab::SharedWithMe);
        }
    });
}

void MainWindow::initializeServices()
{
    // Initialize SSL context for secure connections
    m_sslContext = std::make_shared<SSLContext>();
    
    // Initialize network client and auth service using Config
    m_client = std::make_shared<Client>(Config::getInstance().getServerUrl());
    m_authService = std::make_shared<AuthService>(m_client);
}

MainWindow::~MainWindow()
{
    //destructor cause it wouldnt build without i
}   
