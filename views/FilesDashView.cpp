#include "FilesDashView.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel> // For placeholder main content

FilesDashView::FilesDashView(QWidget *parent) : QWidget(parent) {
    header = new HeaderWidget(this);
    sideNav = new SideNavWidget(this);

    //placeholder main content for now
    QWidget *mainContent = new QWidget(this);
    mainContent->setObjectName("mainContent");
    mainContent->setStyleSheet("background: #1A1A1A;");

    QVBoxLayout *mainContentLayout = new QVBoxLayout(mainContent);
    mainContentLayout->setContentsMargins(0, 0, 0, 0);
    mainContentLayout->setSpacing(0);

    QLabel *contentLabel = new QLabel("Owned Files", mainContent);
    contentLabel->setStyleSheet("color: #E0E0E0; font-size: 16px; font-weight: 500; padding: 16px;");
    mainContentLayout->addWidget(contentLabel);

    // Add a file list widget
    QWidget *fileListWidget = new QWidget(mainContent);
    fileListWidget->setObjectName("fileListWidget");
    QVBoxLayout *fileListLayout = new QVBoxLayout(fileListWidget);
    fileListLayout->setContentsMargins(0, 0, 0, 0);
    fileListLayout->setSpacing(4);

    QStringList files = {"ProjectPlan.docx", "Budget2025.xlsx", "MeetingNotes.pdf", "DesignMockup.png"};
    for (const QString &file : files) {
        QLabel *fileLabel = new QLabel(file, fileListWidget);
        fileLabel->setStyleSheet("color: #E0E0E0; font-size: 14px; padding: 8px 16px;");
        fileListLayout->addWidget(fileLabel);
    }
    mainContentLayout->addWidget(fileListWidget);
    mainContentLayout->addStretch();

    // Horizontal layout for side nav + main content
    QHBoxLayout *hLayout = new QHBoxLayout();
    hLayout->setContentsMargins(0, 0, 0, 0); //this removes margins
    hLayout->setSpacing(0); //this removes spacing between widgets
    hLayout->addWidget(sideNav);
    hLayout->addWidget(mainContent, 1); 

    // Vertical layout for header + rest
    QVBoxLayout *vLayout = new QVBoxLayout(this);
    vLayout->setContentsMargins(0, 0, 0, 0); 
    vLayout->setSpacing(0); 
    vLayout->addWidget(header);
    vLayout->addLayout(hLayout, 1); 

    setLayout(vLayout);
}