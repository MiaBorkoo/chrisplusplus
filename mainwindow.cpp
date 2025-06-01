#include "mainwindow.h"
#include "views/SignUpView.h"
#include "controllers/SignUpController.h"
#include "controllers/FileDashController.h"
#include "controllers/SideNavController.h"
#include "controllers/SharedDashController.h"
#include <QScreen>
#include <QApplication>
#include <QStackedWidget>
#include <QMessageBox>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent): QMainWindow(parent)
{
    setWindowTitle("Login");
    QScreen *screen = QApplication::primaryScreen();
    QRect screenGeometry = screen->geometry();
    setGeometry(screenGeometry);

    m_stack = new QStackedWidget(this);

    //creates login view and controller
    m_loginView = new LoginView(this);
    m_loginController = new LoginController(this);
    m_loginController->setView(m_loginView);

    //creates sign up view and controller
    m_signUpView = new SignUpView(this);
    m_signUpController = new SignUpController(m_signUpView, this);

    m_filesDashView = new FilesDashView(this);
    m_fileDashController = new FileDashController(m_filesDashView->getSearchBar(), m_filesDashView->getFileTable(), this);
   

    m_sharedDashView = new SharedDashView(this);
    m_sharedDashController = new SharedDashController(m_sharedDashView, this);

    // Initialize side nav controller with the FilesDashView's side nav
    m_sideNavController = new SideNavController(m_filesDashView->getSideNav(), this);

    m_stack->addWidget(m_loginView);   //index 0 in the stacked widget
    m_stack->addWidget(m_signUpView);  //index 1 in the stacked widget
    m_stack->addWidget(m_filesDashView);  //index 2 in the stacked widget
    m_stack->addWidget(m_sharedDashView); //index 3 in the stacked widget

    setCentralWidget(m_stack);

    //connect() - This is Qt's function to connect signals to slots
    //switches to sign up view when sign-up button is clicked
    connect(m_loginView, &LoginView::signUpClicked, this, [this]() {
        m_stack->setCurrentWidget(m_signUpView);
    });

    //switches back to login view when login button is clicked on sign-up page
    connect(m_signUpView, &SignUpView::loginRequested, this, [this]() {
        m_stack->setCurrentWidget(m_loginView);
    });

    //switches to files dash view after successful login
    connect(m_loginController, &LoginController::loginSuccessful, this, [this]() {
        m_stack->setCurrentWidget(m_filesDashView);
        m_sideNavController->setActiveTab(" Owned Files");
    });
    
    connect(m_filesDashView, &FilesDashView::fileOpenRequested, this, [this](const QString &fileName) {
        QMessageBox::information(this, "Open File", "You opened: " + fileName);
    });

   
    // Connect upload signal
    connect(m_filesDashView, &FilesDashView::uploadRequested, this, []() {
        qDebug() << "Upload requested";
        QMessageBox::information(nullptr, "Upload", "Would open file dialog to upload a file.\nWaiting for model.");
    });

    connect(m_sharedDashController, &SharedDashController::downloadRequested, this, [this](const QString &fileName) {
        qDebug() << "Attempting to open shared file:" << fileName;
        QMessageBox::information(this, "File Opening", QString("Would open shared file: %1\nWaiting for model.").arg(fileName));
    });

    // Connect side nav signals
    connect(m_sideNavController, &SideNavController::ownedFilesRequested, this, [this]() {
        m_stack->setCurrentWidget(m_filesDashView);
        m_sideNavController->setActiveTab(" Owned Files");
    });

    connect(m_sideNavController, &SideNavController::sharedFilesRequested, this, [this]() {
        m_stack->setCurrentWidget(m_sharedDashView);
        m_sideNavController->setActiveTab(" Shared With Me");
    });

    connect(m_sideNavController, &SideNavController::inboxRequested, this, [this]() {
        // TODO: Implement inbox view -> this depeneds on if we want to keep it
        QMessageBox::information(this, "Inbox", "Inbox view coming soon!");
    });

    connect(m_sideNavController, &SideNavController::logoutRequested, this, [this]() {
        m_stack->setCurrentWidget(m_loginView);
    });

    // Connect stack widget's currentChanged signal to update the side nav controller's view
    connect(m_stack, &QStackedWidget::currentChanged, this, [this](int index) {
        if (index == 2) { // FilesDashView
            m_sideNavController->setView(m_filesDashView->getSideNav());
        } else if (index == 3) { // SharedDashView
            m_sideNavController->setView(m_sharedDashView->getSideNav());
        }
    });

   
}   

MainWindow::~MainWindow() {
    
}
