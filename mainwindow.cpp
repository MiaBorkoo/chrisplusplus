#include "mainwindow.h"
#include "views/SignUpView.h"
#include "controllers/SignUpController.h"
#include <QScreen>
#include <QApplication>
#include <QStackedWidget>

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

    m_stack->addWidget(m_loginView);   //index 0 in the stacked widget
    m_stack->addWidget(m_signUpView);  //index 1 in the stacked widget
    m_stack->addWidget(m_filesDashView);  //index 2 in the stacked widget

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
    });
}   