#include "FileDashController.h"
#include <QLineEdit>
#include <QTableWidget>
#include "../views/FilesDashView.h"
#include <QMessageBox>
#include <QFileDialog>
#include <QInputDialog>
#include <QDir>
#include <iostream>

FileDashController::FileDashController(QLineEdit *searchBar, QTableWidget *fileTable, std::shared_ptr<FileModel> fileModel, QObject *parent)
    : QObject(parent), m_searchBar(searchBar), m_fileTable(fileTable), m_view(nullptr), m_fileModel(fileModel) {
    
    m_view = qobject_cast<FilesDashView*>(m_fileTable->parent()->parent());
    if (m_view) {
        connect(m_view, &FilesDashView::deleteRequested, this, &FileDashController::onDeleteFileRequested);
        connect(m_view, &FilesDashView::downloadRequested, this, &FileDashController::onDownloadFileRequested);
        connect(m_view, &FilesDashView::accessRequested, this, &FileDashController::onAccessRequested);
        connect(m_view, &FilesDashView::uploadRequested, this, [this]() {
            std::cout << "🎯 FILEDASHCONTROLLER: Upload requested from UI" << std::endl;
            QString filePath = QFileDialog::getOpenFileName(m_view,
                tr("Select File to Upload"),
                QDir::homePath(),
                tr("All Files (*.*)"));
            if (!filePath.isEmpty()) {
                std::cout << "📁 FILEDASHCONTROLLER: Selected file: " << filePath.toStdString() << std::endl;
                std::cout << "📤 FILEDASHCONTROLLER: Calling m_fileModel->uploadFile..." << std::endl;
                m_fileModel->uploadFile(filePath);
                std::cout << "✅ FILEDASHCONTROLLER: m_fileModel->uploadFile call completed" << std::endl;
            } else {
                std::cout << "❌ FILEDASHCONTROLLER: No file selected" << std::endl;
            }
        });
    }

    // Connect model signals
    connect(m_fileModel.get(), &FileModel::fileUploaded, this, [this](bool success, const QString &fileName) {
        if (success) {
            // Show success message but don't automatically refresh 
            // since the server might return 500 error after encrypted uploads
            QMessageBox::information(m_view, "Upload Success", 
                "File '" + fileName + "' uploaded successfully!\n\n"
                "Please refresh manually if the file doesn't appear.");
            
            // Optional: Try to refresh, but don't clear UI if it fails
            // m_fileModel->listFiles();
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
            std::cout << "✅ FILEDASHCONTROLLER: Delete successful, refreshing file list from server" << std::endl;
            m_fileModel->listFiles();  // Get fresh data from server
        } else {
            QMessageBox::warning(m_view, "Delete Error", "Failed to delete " + fileName);
        }
    });

    connect(m_fileModel.get(), &FileModel::fileListUpdated, this, 
        [this](const QList<MvcFileInfo>& files, int totalFiles, int currentPage, int totalPages) {
            m_view->clearTable();
            for (const auto &file : files) {
                m_view->addFileRow(file.name, QString::number(file.size), file.uploadDate, file.fileId);
            }
    });

    connect(m_fileModel.get(), &FileModel::errorOccurred, this, [this](const QString &error) {
        QMessageBox::warning(m_view, "Error", error);
    });

    // Connect sharing signals
    connect(m_fileModel.get(), &FileModel::accessGranted, this, [this](bool success, const QString &fileName, const QString &username) {
        if (success) {
            QMessageBox::information(m_view, "Share Success", 
                QString("File '%1' successfully shared with user '%2'!").arg(fileName, username));
            std::cout << "✅ FILEDASHCONTROLLER: File sharing successful" << std::endl;
        } else {
            QMessageBox::warning(m_view, "Share Error", 
                QString("Failed to share file '%1' with user '%2'").arg(fileName, username));
            std::cout << "❌ FILEDASHCONTROLLER: File sharing failed" << std::endl;
        }
    });

    // Connect search bar
    connect(m_searchBar, &QLineEdit::textChanged, this, &FileDashController::handleSearch);
    connect(m_fileTable, &QTableWidget::cellClicked, this, &FileDashController::handleFileSelection);

    // Don't call initial population here - wait for authentication
    // m_fileModel->listFiles();
}

void FileDashController::handleSearch(const QString &text) {
    emit searchRequested(text);
    
    // Hide rows that don't match the search text
    for (int row = 0; row < m_fileTable->rowCount(); ++row) {
        QTableWidgetItem *item = m_fileTable->item(row, 0); 
        if (item) {
            bool matches = text.isEmpty() || 
                         item->text().contains(text, Qt::CaseInsensitive);
            m_fileTable->setRowHidden(row, !matches);
        }
    }
}

void FileDashController::handleFileSelection(int row, int column) {
    QTableWidgetItem *item = m_fileTable->item(row, 0);
    if (item) {
        emit fileSelected(item->text());
    }
}

void FileDashController::onDeleteFileRequested(const QString &fileId, const QString &displayName) {
    QMessageBox::StandardButton reply = QMessageBox::question(
        m_view,
        "Delete File",
        "Are you sure you want to delete '" + displayName + "'?",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::Yes
    );
    if (reply == QMessageBox::Yes) {
        std::cout << "🗑️ FILEDASHCONTROLLER: Deleting file with ID: " << fileId.toStdString() << std::endl;
        m_fileModel->deleteFile(fileId);  // Use fileId for server operation
    }
}

void FileDashController::onDownloadFileRequested(const QString &fileId, const QString &displayName) {
    QString savePath = QFileDialog::getSaveFileName(m_view,
        tr("Save File As"),
        QDir::homePath() + "/" + displayName,  // Use display name for default filename
        tr("All Files (*.*)"));
    if (!savePath.isEmpty()) {
        std::cout << "⬇️ FILEDASHCONTROLLER: Downloading file with ID: " << fileId.toStdString() << std::endl;
        m_fileModel->downloadFile(fileId, savePath);  // Use fileId for server operation
    }
}

void FileDashController::onAccessRequested(const QString &fileId, const QString &displayName) {
    bool ok;
    QString username = QInputDialog::getText(m_view, 
        "Share File", 
        QString("Enter username to share '%1' with:").arg(displayName),
        QLineEdit::Normal, 
        "", 
        &ok);
    
    if (ok && !username.isEmpty()) {
        std::cout << "🤝 FILEDASHCONTROLLER: Sharing file '" << displayName.toStdString() 
                  << "' (ID: " << fileId.toStdString() << ") with user: " << username.toStdString() << std::endl;
        
        // Use the FileModel to grant access with the actual fileId
        m_fileModel->grantAccess(fileId, username);
    } else if (ok) {
        QMessageBox::warning(m_view, "Invalid Input", "Please enter a valid username.");
    }
}

void FileDashController::setFileService(std::shared_ptr<FileService> fileService)
{
    // This should be called after login with properly configured FileService
    std::cout << "FileDashController::setFileService called!" << std::endl;
    
    // Now trigger initial file listing
    if (m_fileModel) {
        std::cout << "Calling m_fileModel->listFiles()..." << std::endl;
        m_fileModel->listFiles();
        std::cout << "m_fileModel->listFiles() completed" << std::endl;
    } else {
        std::cout << "ERROR: m_fileModel is null!" << std::endl;
    }
}