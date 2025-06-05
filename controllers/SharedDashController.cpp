#include "SharedDashController.h"
#include <QListWidget>
#include <QListWidgetItem>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QFileDialog>
#include <QDir>
#include <QMessageBox>
#include <iostream>

SharedDashController::SharedDashController(SharedDashView *view, std::shared_ptr<SharedFileModel> sharedFileModel, QObject *parent)
    : QObject(parent), view(view), m_sharedFileModel(sharedFileModel) {
    
    connectSignals();
    
    // Connect to shared file model signals
    connect(m_sharedFileModel.get(), &SharedFileModel::sharedFileListUpdated,
            this, &SharedDashController::handleSharedFileListUpdated);
    connect(m_sharedFileModel.get(), &SharedFileModel::fileDownloaded,
            this, &SharedDashController::handleFileDownloaded);
    connect(m_sharedFileModel.get(), &SharedFileModel::errorOccurred,
            this, &SharedDashController::handleError);
    
    // Load shared files when controller is created
    loadSharedFiles();
}

void SharedDashController::setFileService(std::shared_ptr<FileService> fileService) {
    // The SharedFileModel should already have the FileService
    // Trigger a reload of shared files
    loadSharedFiles();
}

void SharedDashController::loadSharedFiles() {
    if (m_sharedFileModel) {
        std::cout << "🔄 SHAREDDASHCONTROLLER: Loading shared files..." << std::endl;
        m_sharedFileModel->listSharedFiles();
    }
}

void SharedDashController::connectSignals() {
    connect(view->getSearchBar(), &QLineEdit::textChanged, this, [this](const QString &query) {
        QListWidget *list = view->getFileList();
        for (int i = 0; i < list->count(); ++i) {
            QListWidgetItem *item = list->item(i);
            QWidget *widget = list->itemWidget(item);
            QLabel *fileLabel = widget->findChild<QLabel*>("sharedFileLabel");
            bool match = fileLabel && fileLabel->text().contains(query, Qt::CaseInsensitive);
            item->setHidden(!match);
        }
    });
}

void SharedDashController::handleSharedFileListUpdated(const QList<MvcSharedFileInfo>& files, int totalFiles, int currentPage, int totalPages) {
    std::cout << "📋 SHAREDDASHCONTROLLER: Received " << files.size() << " shared files" << std::endl;
    
    // Clear existing items
    view->getFileList()->clear();
    
    for (int i = 0; i < files.size(); ++i) {
        const MvcSharedFileInfo& file = files[i];
        
        std::cout << "  - Adding shared file: " << file.name.toStdString() << " from " << file.sharedBy.toStdString() << std::endl;
        
        view->addSharedFile(file.name, file.sharedBy);
        
        // Connect download button
        QPushButton *downloadBtn = view->getDownloadButtonForRow(i);
        if (downloadBtn) {
            connect(downloadBtn, &QPushButton::clicked, this, [this, file]() {
                onDownloadSharedFileRequested(file.fileId, file.name);
            });
        }
    }
    
    std::cout << "✅ SHAREDDASHCONTROLLER: Shared file list updated successfully" << std::endl;
}

void SharedDashController::onDownloadSharedFileRequested(const QString &fileId, const QString &displayName) {
    QString savePath = QFileDialog::getSaveFileName(view,
        tr("Save Shared File As"),
        QDir::homePath() + "/" + displayName,
        tr("All Files (*.*)"));
    
    if (!savePath.isEmpty()) {
        std::cout << "⬇️ SHAREDDASHCONTROLLER: Downloading shared file with ID: " << fileId.toStdString() << std::endl;
        m_sharedFileModel->downloadSharedFile(fileId, savePath);
        emit downloadRequested(displayName);
    }
}

void SharedDashController::handleFileDownloaded(bool success, const QString& fileName) {
    if (success) {
        QMessageBox::information(view, "Download Complete", 
            QString("Shared file '%1' downloaded successfully!").arg(fileName));
        std::cout << "✅ SHAREDDASHCONTROLLER: Download completed: " << fileName.toStdString() << std::endl;
    } else {
        QMessageBox::warning(view, "Download Failed", 
            QString("Failed to download shared file '%1'").arg(fileName));
        std::cout << "❌ SHAREDDASHCONTROLLER: Download failed: " << fileName.toStdString() << std::endl;
    }
}

void SharedDashController::handleError(const QString& error) {
    QMessageBox::warning(view, "Error", "Shared files error: " + error);
    std::cout << "❌ SHAREDDASHCONTROLLER: Error: " << error.toStdString() << std::endl;
} 