#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include <memory>
#include "views/LoginView.h"
#include "controllers/LoginController.h"
#include "views/SignUpView.h"
#include "controllers/SignUpController.h"
#include "views/FilesDashView.h"
#include "controllers/FileDashController.h"
#include "views/SharedDashView.h"
#include "controllers/SideNavController.h"
#include "controllers/SharedDashController.h"
#include "models/FileModel.h"
#include "models/LoginModel.h"
#include "services/files/FileService.h"
#include "views/AccountSection.h"
#include "controllers/AccountController.h"
#include "services/auth/AuthService.h"
#include "network/Client.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

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
    HeaderWidget* m_headerWidget;
    AccountSection* m_accountSection;
    AccountController* m_accountController;
    std::shared_ptr<Client> m_client;
    std::shared_ptr<AuthService> m_authService;
    std::shared_ptr<FileService> m_fileService;
    std::shared_ptr<FileModel> m_fileModel;
    std::shared_ptr<LoginModel> m_loginModel;

    void initializeServices();
};

#endif // MAINWINDOW_H
