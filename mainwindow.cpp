#include "mainwindow.h"
#include <QLabel>
#include <QVBoxLayout>
#include <QWidget>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    auto centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    auto layout = new QVBoxLayout(centralWidget);
    auto label = new QLabel("ChrisPlusPlus - File Transfer Ready!", this);
    layout->addWidget(label);
    
    setWindowTitle("ChrisPlusPlus");
    resize(400, 300);
}

MainWindow::~MainWindow()
{
}
