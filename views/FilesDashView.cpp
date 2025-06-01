#include "FilesDashView.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QTableWidget>
#include <QHeaderView>
#include <QPushButton>
#include <QIcon>

FilesDashView::FilesDashView(QWidget *parent) : QWidget(parent) {
    header = new HeaderWidget(this);
    sideNav = new SideNavWidget(this);

    // main content widget
    QWidget *mainContent = new QWidget(this);
    mainContent->setObjectName("mainContent");

    QVBoxLayout *mainContentLayout = new QVBoxLayout(mainContent);
    mainContentLayout->setContentsMargins(16, 16, 16, 16);
    mainContentLayout->setSpacing(12);

    //horizontal layout for search bar and upload button
    QHBoxLayout *topLayout = new QHBoxLayout();
    topLayout->setSpacing(8);

    
    searchBar = new QLineEdit(mainContent);
    searchBar->setObjectName("searchBar");
    searchBar->setPlaceholderText("Search files...");
    topLayout->addWidget(searchBar, 1);

    // Upload button
    QPushButton *uploadButton = new QPushButton("Upload File", mainContent);
    uploadButton->setObjectName("uploadButton");
    connect(uploadButton, &QPushButton::clicked, this, &FilesDashView::uploadRequested);
    topLayout->addWidget(uploadButton);

    mainContentLayout->addLayout(topLayout);

    // File table
    fileTable = new QTableWidget(mainContent);
    fileTable->setObjectName("fileTable");
    fileTable->setAlternatingRowColors(true);
    fileTable->setColumnCount(4);
    fileTable->setHorizontalHeaderLabels({"Name", "Size", "Date Uploaded", "Actions"});
    fileTable->verticalHeader()->setVisible(false);
    fileTable->setSelectionMode(QAbstractItemView::SingleSelection);
    fileTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    fileTable->horizontalHeader()->setStretchLastSection(true);
    fileTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    mainContentLayout->addWidget(fileTable);

    //this connects double-click to emit fileOpenRequested -> this will change when we add a model
    connect(fileTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int column) {
        QTableWidgetItem *item = fileTable->item(row, 0);
        if (item) {
            QString fileName = item->text();
            emit fileOpenRequested(fileName);
        }
    });

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

void FilesDashView::addFileRow(const QString &name, const QString &size, const QString &date) {
    int row = fileTable->rowCount();
    fileTable->insertRow(row);
    fileTable->setItem(row, 0, new QTableWidgetItem(name));
    fileTable->setItem(row, 1, new QTableWidgetItem(size));
    fileTable->setItem(row, 2, new QTableWidgetItem(date));

    // Create actions widget (access + delete)
    QWidget *actionsWidget = new QWidget();
    QHBoxLayout *actionsLayout = new QHBoxLayout(actionsWidget);
    actionsLayout->setContentsMargins(0, 0, 0, 0);
    actionsLayout->setSpacing(6);

    // Access button (with text)
    QPushButton *accessButton = new QPushButton("Access");
    accessButton->setObjectName("accessButton");
    connect(accessButton, &QPushButton::clicked, this, [this, name]() {
        emit accessRequested(name);
    });
    actionsLayout->addWidget(accessButton);

    // Delete button (red trash icon)
    QPushButton *deleteButton = new QPushButton();
    deleteButton->setToolTip("Delete File");
    deleteButton->setFixedSize(28, 28); 
    deleteButton->setIcon(QIcon(":/assets/trash.svg")); 
    deleteButton->setIconSize(QSize(18, 18));
    deleteButton->setObjectName("deleteButton");
    connect(deleteButton, &QPushButton::clicked, this, [this, name]() {
        emit deleteRequested(name);
    });
    actionsLayout->addWidget(deleteButton);

    actionsLayout->addStretch();
    fileTable->setCellWidget(row, 3, actionsWidget);
}

QLineEdit* FilesDashView::getSearchBar() const { return searchBar; }
QTableWidget* FilesDashView::getFileTable() const { return fileTable; }
SideNavWidget* FilesDashView::getSideNav() const { return sideNav; }