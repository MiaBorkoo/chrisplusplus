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
    //initialising header and side navigation
    header = new HeaderWidget(this);
    sideNav = new SideNavWidget(this);
    sideNav->setActiveTab("Shared With Me"); 

    // This is our main content widget
    QWidget *mainContent = new QWidget(this);
    mainContent->setObjectName("mainContent");

    QVBoxLayout *mainContentLayout = new QVBoxLayout(mainContent);
    mainContentLayout->setContentsMargins(16, 16, 16, 16);
    mainContentLayout->setSpacing(12);

    //making the search bar
    searchBar = new QLineEdit(mainContent);
    searchBar->setObjectName("searchBar");
    searchBar->setPlaceholderText("Search shared files...");
    mainContentLayout->addWidget(searchBar);

    //list that will contain the shared files
    fileList = new QListWidget(mainContent);
    fileList->setObjectName("fileList");
    fileList->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    fileList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    fileList->setSpacing(8);
    fileList->setSelectionMode(QAbstractItemView::NoSelection);
    
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

void SharedDashView::addSharedFile(const QString &fileName, const QString &sharedBy) {
    QListWidgetItem *item = new QListWidgetItem(fileList);
    QWidget *fileWidget = new QWidget(fileList);
    fileWidget->setObjectName("sharedFileWidget");
    QHBoxLayout *layout = new QHBoxLayout(fileWidget);
    layout->setContentsMargins(12, 4, 12, 4);
    layout->setSpacing(8);
    

    QLabel *fileLabel = new QLabel(fileName, fileWidget);
    fileLabel->setObjectName("sharedFileLabel");
    QLabel *sharedByLabel = new QLabel("Shared by: " + sharedBy, fileWidget);
    sharedByLabel->setObjectName("sharedByLabel");

    QPushButton *openButton = new QPushButton("Download", fileWidget);
    openButton->setObjectName("downloadButton");


    layout->addWidget(fileLabel);
    layout->addStretch();
    layout->addWidget(sharedByLabel);
    layout->addWidget(openButton);

    fileWidget->setFixedHeight(60);
    item->setSizeHint(fileWidget->sizeHint());
    fileList->setItemWidget(item, fileWidget);
}

QPushButton* SharedDashView::getDownloadButtonForRow(int row) const {
    if (row < 0 || row >= fileList->count()) return nullptr;
    QListWidgetItem *item = fileList->item(row);
    QWidget *fileWidget = fileList->itemWidget(item);
    if (!fileWidget) return nullptr;
    return fileWidget->findChild<QPushButton*>("downloadButton");
}

QListWidget* SharedDashView::getFileList() const { return fileList; }
SideNavWidget* SharedDashView::getSideNav() const { return sideNav; }
QLineEdit* SharedDashView::getSearchBar() const { return searchBar; }