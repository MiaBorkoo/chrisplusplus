#include "SharedDashView.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidget>
#include <QListWidgetItem>
#include <QWidget>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>

SharedDashView::SharedDashView(QWidget *parent) : QWidget(parent) {
    // Initialize header and side navigation
    header = new HeaderWidget(this);
    sideNav = new SideNavWidget(this);

    // Main content widget
    QWidget *mainContent = new QWidget(this);
    mainContent->setObjectName("mainContent");

    QVBoxLayout *mainContentLayout = new QVBoxLayout(mainContent);
    mainContentLayout->setContentsMargins(16, 16, 16, 16);
    mainContentLayout->setSpacing(12);

    // Create search bar
    searchBar = new QLineEdit(mainContent);
    searchBar->setObjectName("searchBar");
    searchBar->setPlaceholderText("Search shared files...");
    mainContentLayout->addWidget(searchBar);

    // File list
    fileList = new QListWidget(mainContent);
    fileList->setObjectName("fileList");
    fileList->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    fileList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    fileList->setSpacing(8);
    fileList->setStyleSheet("QListWidget { background-color: transparent; border: none; }");

    // Placeholder data for shared files
    QStringList sharedFiles = {
        "ProjectPlan.docx (from user1@example.com)",
        "Budget2025.xlsx (from user2@example.com)",
        "MeetingNotes.pdf (from user3@example.com)",
        "DesignMockup.png (from user1@example.com)"
    };
    for (const QString &file : sharedFiles) {
        QListWidgetItem *item = new QListWidgetItem(fileList);
        QWidget *fileWidget = new QWidget(fileList);
        fileWidget->setObjectName("sharedFileWidget");
        QHBoxLayout *layout = new QHBoxLayout(fileWidget);
        layout->setContentsMargins(12, 8, 12, 8);
        layout->setSpacing(8);

        QLabel *fileLabel = new QLabel(file.split(" (from ").first(), fileWidget);
        fileLabel->setObjectName("sharedFileLabel");
        QLabel *sharedByLabel = new QLabel("Shared by: " + file.split(" (from ").last().chopped(1), fileWidget);
        sharedByLabel->setObjectName("sharedByLabel");

        QPushButton *openButton = new QPushButton("Download", fileWidget);
        openButton->setObjectName("downloadButton");
        connect(openButton, &QPushButton::clicked, this, [this, file]() {
            emit fileOpenRequested(file.split(" (from ").first());
        });

        layout->addWidget(fileLabel);
        layout->addStretch();
        layout->addWidget(sharedByLabel);
        layout->addWidget(openButton);

        fileWidget->setFixedHeight(60);
        item->setSizeHint(fileWidget->sizeHint());
        fileList->setItemWidget(item, fileWidget);
    }

    mainContentLayout->addWidget(fileList);

    // Horizontal layout for side nav + main content
    QHBoxLayout *hLayout = new QHBoxLayout();
    hLayout->setContentsMargins(0, 0, 0, 0);
    hLayout->setSpacing(0);
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

QListWidget* SharedDashView::getFileList() const { return fileList; }
SideNavWidget* SharedDashView::getSideNav() const { return sideNav; }
QLineEdit* SharedDashView::getSearchBar() const { return searchBar; }