#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include "views/LoginView.h"
#include "controllers/LoginController.h"
#include "views/SignUpView.h"

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
};

#endif // MAINWINDOW_H
