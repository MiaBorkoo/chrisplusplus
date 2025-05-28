#include "FileDashController.h"

FileDashController::FileDashController(QLineEdit *searchBar, QTableWidget *fileTable, QObject *parent)
    : QObject(parent), searchBar(searchBar), fileTable(fileTable) {
    connect(searchBar, &QLineEdit::textChanged, this, &FileDashController::handleSearchInput);
    connect(fileTable, &QTableWidget::cellClicked, this, &FileDashController::handleFileSelection);
}

void FileDashController::handleSearchInput(const QString &text) {
    emit searchRequested(text);
}

void FileDashController::handleFileSelection(int row, int column) {
    QTableWidgetItem *item = fileTable->item(row, 0);
    if (item) {
        emit fileSelected(item->text());
    }
}