#include "FilesDashView.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QTableWidget>
#include <QHeaderView>
#include <QPushButton>

FilesDashView::FilesDashView(QWidget *parent) : QWidget(parent) {
    header = new HeaderWidget(this);
    sideNav = new SideNavWidget(this);

    // main content widget
    QWidget *mainContent = new QWidget(this);
    mainContent->setObjectName("mainContent");

    QVBoxLayout *mainContentLayout = new QVBoxLayout(mainContent);
    mainContentLayout->setContentsMargins(16, 16, 16, 16);
    mainContentLayout->setSpacing(12);

    // Horizontal layout for search bar and upload button
    QHBoxLayout *topLayout = new QHBoxLayout();
    topLayout->setSpacing(8);

    // Search bar
    searchBar = new QLineEdit(mainContent);
    searchBar->setObjectName("searchBar");
    // Placeholder text is a UX feature, keep it
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
    // Only keep logic, remove visual styling (alternating row colors, grid, etc.)
    fileTable->setColumnCount(3);
    fileTable->setHorizontalHeaderLabels({"Name", "Size", "Date Uploaded"});
    fileTable->verticalHeader()->setVisible(false);
    fileTable->setSelectionMode(QAbstractItemView::SingleSelection);
    fileTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    fileTable->horizontalHeader()->setStretchLastSection(true);
    fileTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    mainContentLayout->addWidget(fileTable);

    // Placeholder table with sample data -> remove this later
    QStringList files = {"ProjectPlan.docx", "Budget2025.xlsx", "MeetingNotes.pdf", "DesignMockup.png"};
    fileTable->setRowCount(files.size());
    for (int i = 0; i < files.size(); ++i) {
        QTableWidgetItem *nameItem = new QTableWidgetItem(files[i]);
        QTableWidgetItem *sizeItem = new QTableWidgetItem("1.2 MB");
        QTableWidgetItem *dateItem = new QTableWidgetItem("2025-05-27");
        fileTable->setItem(i, 0, nameItem);
        fileTable->setItem(i, 1, sizeItem);
        fileTable->setItem(i, 2, dateItem);
    }

    // Connect double-click to emit fileOpenRequested
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

QLineEdit* FilesDashView::getSearchBar() const { return searchBar; }
QTableWidget* FilesDashView::getFileTable() const { return fileTable; }
SideNavWidget* FilesDashView::getSideNav() const { return sideNav; }