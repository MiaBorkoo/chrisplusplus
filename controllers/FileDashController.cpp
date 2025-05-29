#include "FileDashController.h"
#include <QLineEdit>
#include <QTableWidget>

FileDashController::FileDashController(QLineEdit *searchBar, QTableWidget *fileTable, QObject *parent)
    : QObject(parent), searchBar(searchBar), fileTable(fileTable) {
    connectSignals();
}

void FileDashController::connectSignals() {
    connect(searchBar, &QLineEdit::textChanged, this, [this](const QString &query) {
        for (int i = 0; i < fileTable->rowCount(); ++i) {
            bool match = fileTable->item(i, 0)->text().contains(query, Qt::CaseInsensitive);
            fileTable->setRowHidden(i, !match);
        }
    });
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