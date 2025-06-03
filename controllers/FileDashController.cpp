#include "FileDashController.h"
#include <QLineEdit>
#include <QTableWidget>
#include "../views/FilesDashView.h"
#include "AccessDialog.h"
#include "AccessController.h"
#include <QMessageBox>

FileDashController::FileDashController(QLineEdit *searchBar, QTableWidget *fileTable, QObject *parent)
    : QObject(parent), m_searchBar(searchBar), m_fileTable(fileTable), m_view(nullptr) {
    // Placeholder data for files
    m_files = {
        {"ProjectPlan.docx", "1.2 MB", "2025-05-27"},
        {"Budget2025.xlsx", "1.2 MB", "2025-05-27"},
        {"MeetingNotes.pdf", "1.2 MB", "2025-05-27"},
        {"DesignMockup.png", "1.2 MB", "2025-05-27"}
    };
    m_view = qobject_cast<FilesDashView*>(m_fileTable->parent()->parent());
    if (m_view) {
        connect(m_view, &FilesDashView::deleteRequested, this, &FileDashController::onDeleteFileRequested);
    }
    // Connect signals
    connect(m_searchBar, &QLineEdit::textChanged, this, [this](const QString &query) {
        for (int i = 0; i < m_fileTable->rowCount(); ++i) {
            bool match = m_fileTable->item(i, 0)->text().contains(query, Qt::CaseInsensitive);
            m_fileTable->setRowHidden(i, !match);
        }
    });
    connect(m_fileTable, &QTableWidget::cellClicked, this, &FileDashController::handleFileSelection);
    if (m_view) {
        connect(m_view, &FilesDashView::accessRequested, this, &FileDashController::showAccessDialogForFile);
    }
    repopulateTable();
}

void FileDashController::handleSearch(const QString &text) {
    emit searchRequested(text);
}

void FileDashController::handleFileSelection(int row, int column) {
    QTableWidgetItem *item = m_fileTable->item(row, 0);
    if (item) {
        emit fileSelected(item->text());
    }
}

void FileDashController::showAccessDialogForFile(const QString &fileName) {
    QStringList users = m_fileAccess[fileName];
    AccessDialog *dialog = new AccessDialog(fileName, users, nullptr);
    AccessController *accessController = new AccessController(fileName, users, dialog);
    accessController->setView(dialog);
    
    // Connect ACL change signal to bubble upward
    connect(accessController, &AccessController::aclChanged,
            this, [this](const QString &fname, const QStringList &acl){
                m_fileAccess[fname] = acl;           // keep UI model in sync
                emit accessChanged(fname, acl);      // bubble up
            });
    
    dialog->exec();
    // After dialog closes, update m_fileAccess with any changes
    m_fileAccess[fileName] = accessController->getUsers();
    
    // Clean up
    accessController->deleteLater();
    dialog->deleteLater();
}

void FileDashController::onDeleteFileRequested(const QString &fileName) {
    QMessageBox::StandardButton reply = QMessageBox::question(
        m_view,
        "Delete File",
        "Are you sure you want to delete this file?",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::Yes
    );
    if (reply == QMessageBox::Yes) {
        // Remove from m_files
        auto it = std::remove_if(m_files.begin(), m_files.end(), [&](const FileRow &row) {
            return row.name == fileName;
        });
        m_files.erase(it, m_files.end());
        repopulateTable();
    }
}

void FileDashController::repopulateTable() {
    if (m_view) m_view->clearTable();
    for (const auto &file : m_files) {
        if (m_view) {
            m_view->addFileRow(file.name, file.size, file.date);
        }
    }
}