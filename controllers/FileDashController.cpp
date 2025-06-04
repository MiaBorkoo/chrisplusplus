#include "FileDashController.h"
#include <QLineEdit>
#include <QTableWidget>
#include "../views/FilesDashView.h"
#include <QMessageBox>

FileDashController::FileDashController(QLineEdit *searchBar, QTableWidget *fileTable, std::shared_ptr<FileModel> fileModel, QObject *parent)
    : QObject(parent), m_searchBar(searchBar), m_fileTable(fileTable), m_view(nullptr), m_fileModel(fileModel) {
    
    m_view = qobject_cast<FilesDashView*>(m_fileTable->parent()->parent());
    if (m_view) {
        connect(m_view, &FilesDashView::deleteRequested, this, &FileDashController::onDeleteFileRequested);
        connect(m_view, &FilesDashView::uploadRequested, this, [this]() {
            // TODO: Show file dialog and get file path
            QString filePath = ""; // Get from dialog
            if (!filePath.isEmpty()) {
                m_fileModel->uploadFile(filePath);
            }
        });
        connect(m_view, &FilesDashView::downloadRequested, this, [this](const QString &fileName) {
            // TODO: Show save dialog and get save path
            QString savePath = ""; // Get from dialog
            if (!savePath.isEmpty()) {
                m_fileModel->downloadFile(fileName, savePath);
            }
        });
    }

    // Connect model signals
    connect(m_fileModel.get(), &FileModel::fileUploaded, this, [this](bool success, const QString &fileName) {
        if (success) {
            repopulateTable();
        } else {
            QMessageBox::warning(m_view, "Upload Error", "Failed to upload " + fileName);
        }
    });

    connect(m_fileModel.get(), &FileModel::fileDownloaded, this, [this](bool success, const QString &fileName) {
        if (!success) {
            QMessageBox::warning(m_view, "Download Error", "Failed to download " + fileName);
        }
    });

    connect(m_fileModel.get(), &FileModel::fileDeleted, this, [this](bool success, const QString &fileName) {
        if (success) {
            repopulateTable();
        } else {
            QMessageBox::warning(m_view, "Delete Error", "Failed to delete " + fileName);
        }
    });

    connect(m_fileModel.get(), &FileModel::fileListUpdated, this, 
        [this](const QList<FileInfo>& files, int totalFiles, int currentPage, int totalPages) {
            m_view->clearTable();
            for (const auto &file : files) {
                m_view->addFileRow(file.name, QString::number(file.size), file.uploadDate);
            }
    });

    connect(m_fileModel.get(), &FileModel::errorOccurred, this, [this](const QString &error) {
        QMessageBox::warning(m_view, "Error", error);
    });

    // Connect search bar
    connect(m_searchBar, &QLineEdit::textChanged, this, &FileDashController::handleSearch);
    connect(m_fileTable, &QTableWidget::cellClicked, this, &FileDashController::handleFileSelection);

    // Initial population
    m_fileModel->listFiles();
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