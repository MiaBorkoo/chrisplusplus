#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include "views/LoginView.h"
#include "controllers/LoginController.h"
#include "views/SignUpView.h"
#include "controllers/SignUpController.h"
#include "views/FilesDashView.h"
#include "controllers/FileDashController.h"
#include "views/SharedDashView.h"
#include "controllers/SideNavController.h"
#include "controllers/SharedDashController.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);

private:
    QStackedWidget *m_stack;
    LoginView *m_loginView;
    LoginController *m_loginController;
    SignUpView *m_signUpView;
    SignUpController *m_signUpController;
    FilesDashView *m_filesDashView;
    FileDashController *m_fileDashController;
    SharedDashView *m_sharedDashView;
    SharedDashController *m_sharedDashController;
    SideNavController *m_sideNavController;
};

#endif // MAINWINDOW_H
