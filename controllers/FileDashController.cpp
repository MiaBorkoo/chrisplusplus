#include "FileDashController.h"
#include <QLineEdit>
#include <QTableWidget>
#include "../views/FilesDashView.h"

FileDashController::FileDashController(QLineEdit *searchBar, QTableWidget *fileTable, QObject *parent)
    : QObject(parent), searchBar(searchBar), fileTable(fileTable) {
    // Placeholder data for files
    struct FileRow { QString name; QString size; QString date; };
    QList<FileRow> files = {
        {"ProjectPlan.docx", "1.2 MB", "2025-05-27"},
        {"Budget2025.xlsx", "1.2 MB", "2025-05-27"},
        {"MeetingNotes.pdf", "1.2 MB", "2025-05-27"},
        {"DesignMockup.png", "1.2 MB", "2025-05-27"}
    };
    FilesDashView *view = qobject_cast<FilesDashView*>(fileTable->parent()->parent());
    if (view) {
        for (const auto &file : files) {
            view->addFileRow(file.name, file.size, file.date);
        }
    }
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