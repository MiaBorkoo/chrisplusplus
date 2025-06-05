#include "mainwindow.h"
#include "views/SignUpView.h"
#include "controllers/SignUpController.h"
#include "controllers/FileDashController.h"
#include "controllers/SideNavController.h"
#include "controllers/SharedDashController.h"
#include "controllers/AccessController.h"
#include "views/AccountSection.h"
#include "controllers/AccountController.h"
#include "utils/Config.h"
#include <QScreen>
#include <QApplication>
#include <QStackedWidget>
#include <QMessageBox>
#include <QFile>

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

    // Initialize network client and services using Config
    auto client = std::make_shared<Client>(Config::getInstance().getServerUrl());
    m_fileService = std::make_shared<FileService>(client);
    m_fileModel = std::make_shared<FileModel>(m_fileService);
    m_accessModel = std::make_shared<AccessModel>(m_fileService);

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
        m_stack->setCurrentWidget(m_filesDashView);
        m_sideNavController->setActiveTab(SideNavTab::OwnedFiles);
    });
    
    connect(m_filesDashView, &FilesDashView::fileOpenRequested, this, [this](const QString &fileName) {
        QMessageBox::information(this, "Open File", "You opened: " + fileName);
    });

    // Connect access management
    connect(m_filesDashView, &FilesDashView::accessRequested, this, [this](const QString &fileName) {
        auto accessDialog = new AccessDialog(fileName, QStringList(), this);
        auto accessController = new AccessController(fileName, m_accessModel, this);
        accessController->setView(accessDialog);
        accessDialog->show();
    });

    // Connect upload signal
    connect(m_filesDashView, &FilesDashView::uploadRequested, this, []() {
        QMessageBox::information(nullptr, "Upload", "Would open file dialog to upload a file.\nWaiting for model.");
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
    // Initialize network client and auth service using Config
    m_client = std::make_shared<Client>(Config::getInstance().getServerUrl());
    m_authService = std::make_shared<AuthService>(m_client);
}

MainWindow::~MainWindow()
{
    //destructor cause it wouldnt build without i
}   
