#include "FilesDashView.h"
#include "HeaderWidget.h"
#include "SideNavWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>

FilesDashView::FilesDashView(QWidget *parent) : QWidget(parent) {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(0);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    // Create header
    m_header = new HeaderWidget(this);
    mainLayout->addWidget(m_header);

    // Create main content area
    QHBoxLayout *contentLayout = new QHBoxLayout();
    contentLayout->setSpacing(0);
    contentLayout->setContentsMargins(0, 0, 0, 0);

    // Create side navigation
    m_sideNav = new SideNavWidget(this);
    contentLayout->addWidget(m_sideNav);

    // Create file dashboard area
    QWidget *dashArea = new QWidget(this);
    dashArea->setObjectName("mainContent");
    QVBoxLayout *dashLayout = new QVBoxLayout(dashArea);

    // Create search bar
    m_searchBar = new QLineEdit(this);
    m_searchBar->setObjectName("searchBar");
    m_searchBar->setPlaceholderText("Search files...");
    dashLayout->addWidget(m_searchBar);

    // Create upload button
    m_uploadButton = new QPushButton("Upload", this);
    m_uploadButton->setObjectName("uploadButton");
    dashLayout->addWidget(m_uploadButton);

    // Create file table
    m_fileTable = new QTableWidget(this);
    m_fileTable->setObjectName("fileTable");
    m_fileTable->setColumnCount(3);
    m_fileTable->setHorizontalHeaderLabels({"Name", "Size", "Date"});
    m_fileTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_fileTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_fileTable->setSelectionMode(QAbstractItemView::SingleSelection);
    dashLayout->addWidget(m_fileTable);

    contentLayout->addWidget(dashArea);
    mainLayout->addLayout(contentLayout);

    // Connect signals
    connect(m_uploadButton, &QPushButton::clicked, this, &FilesDashView::uploadRequested);
}

void FilesDashView::addFileRow(const QString &name, const QString &size, const QString &date) {
    int row = m_fileTable->rowCount();
    m_fileTable->insertRow(row);
    m_fileTable->setItem(row, 0, new QTableWidgetItem(name));
    m_fileTable->setItem(row, 1, new QTableWidgetItem(size));
    m_fileTable->setItem(row, 2, new QTableWidgetItem(date));
}

void FilesDashView::clearTable() {
    m_fileTable->setRowCount(0);
}

QLineEdit* FilesDashView::getSearchBar() const {
    return m_searchBar;
}

QTableWidget* FilesDashView::getFileTable() const {
    return m_fileTable;
}

SideNavWidget* FilesDashView::getSideNav() const {
    return m_sideNav;
}

HeaderWidget* FilesDashView::getHeader() const {
    return m_header;
}