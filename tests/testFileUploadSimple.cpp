#include <QApplication>
#include <QFileDialog>
#include <QMessageBox>
#include <QTimer>
#include <QDir>
#include <QFileInfo>
#include <iostream>
#include <iomanip>
#include "../sockets/SSLContext.h"
#include "../fileIO/fileTransfer.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    std::cout << "=== Simple File Upload Debug ===" << std::endl;
    
    try {
        // Initialize SSL
        SSLContext::initializeOpenSSL();
        SSLContext sslContext;
        FileTransfer fileTransfer(sslContext);
        
        // Configure for httpbin.org
        fileTransfer.setServer("httpbin.org", "443");
        
        // Get file to upload
        QString filePath = QFileDialog::getOpenFileName(
            nullptr, "Select ANY file to upload", QDir::homePath(), "All Files (*.*)"
        );
        
        if (filePath.isEmpty()) {
            std::cout << "No file selected" << std::endl;
            return 0;
        }
        
        QFileInfo fileInfo(filePath);
        std::cout << "Uploading: " << filePath.toStdString() << std::endl;
        std::cout << "Size: " << fileInfo.size() << " bytes" << std::endl;
        
        // Simple progress callback with just console output
        auto progressCallback = [](qint64 transferred, qint64 total) -> bool {
            double percent = (total > 0) ? (double(transferred) / total) * 100.0 : 0.0;
            std::cout << "Progress: " << transferred << "/" << total 
                      << " bytes (" << std::fixed << std::setprecision(1) << percent << "%)" << std::endl;
            
            // Add debug for when we finish sending
            if (transferred >= total) {
                std::cout << "🔄 File data sent completely! Now waiting for server response..." << std::endl;
            }
            
            return true; // Always continue
        };
        
        std::cout << "Starting upload..." << std::endl;
        
        // Try the upload - this should work for any size
        TransferResult result = fileTransfer.uploadFile(
            filePath,
            "/post",
            progressCallback,
            1  // Just 1 attempt for debugging
        );
        
        std::cout << "🔍 Upload function returned!" << std::endl;
        
        if (result.success) {
            std::cout << "\n✅ SUCCESS!" << std::endl;
            std::cout << "Bytes transferred: " << result.bytesTransferred << std::endl;
            std::cout << "Server response (first 500 chars):" << std::endl;
            std::cout << result.serverResponse.left(500).toStdString() << std::endl;
            
            QMessageBox::information(nullptr, "Upload Success", 
                QString("Upload completed!\n%1 bytes transferred").arg(result.bytesTransferred));
        } else {
            std::cout << "\n❌ FAILED!" << std::endl;
            std::cout << "Error: " << result.errorMessage.toStdString() << std::endl;
            
            QMessageBox::critical(nullptr, "Upload Failed", result.errorMessage);
        }
        
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        QMessageBox::critical(nullptr, "Error", QString("Exception: %1").arg(e.what()));
    }
    
    std::cout << "🏁 Program ending..." << std::endl;
    QTimer::singleShot(100, &app, &QApplication::quit);
    return app.exec();
} 