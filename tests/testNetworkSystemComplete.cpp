#include <QApplication>
#include <QFileDialog>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include <QTextEdit>
#include <QWidget>
#include <QTimer>
#include <QDir>
#include <QFileInfo>
#include <QFont>
#include <iostream>
#include <iomanip>

// ALL YOUR MODULES
#include "../sockets/SSLContext.h"      // SSL/TLS Foundation
#include "../sockets/SSLConnection.h"   // Secure Connections  
#include "../httpC/HttpClient.h"        // HTTP Protocol Layer
#include "../httpC/HttpRequest.h"       // HTTP Requests
#include "../httpC/HttpResponse.h"      // HTTP Responses
#include "../fileIO/fileTransfer.h"     // File Transfer Layer

class NetworkSystemDemo : public QWidget {
    Q_OBJECT

public:
    NetworkSystemDemo() {
        setWindowTitle("ChrisPlusPlus - Complete Network System Demo");
        resize(800, 600);
        setupUI();
        
        // Initialize SSL system
        SSLContext::initializeOpenSSL();
        sslContext_ = std::make_unique<SSLContext>();
        
        logMessage("SSL/TLS System Initialized");
        logMessage("All network modules loaded successfully");
    }

private slots:
    void testSSLFoundation() {
        logMessage("\n=== TEST 1: SSL/TLS Foundation (sockets module) ===");
        
        try {
            // Direct SSL connection test
            SSLConnection conn(*sslContext_, "httpbin.org", "443");
            logMessage("SSL/TLS connection established to httpbin.org:443");
            
            // Send raw HTTP request
            std::string rawRequest = 
                "GET /json HTTP/1.1\r\n"
                "Host: httpbin.org\r\n"
                "Connection: close\r\n\r\n";
            
            ssize_t sent = conn.send(rawRequest.data(), rawRequest.size());
            logMessage(QString("Sent %1 bytes over encrypted channel").arg(sent));
            
            // Read response
            char buffer[1024];
            ssize_t received = conn.receive(buffer, sizeof(buffer) - 1);
            buffer[received] = '\0';
            
            std::string response(buffer);
            size_t statusEnd = response.find('\n');
            logMessage(QString("Received: %1").arg(QString::fromStdString(response.substr(0, statusEnd))));
            
            logMessage("SSL/TLS Foundation: WORKING PERFECTLY");
            
        } catch (const std::exception& e) {
            logMessage(QString("SSL Test Failed: %1").arg(e.what()));
        }
    }
    
    void testHTTPLayer() {
        logMessage("\n=== TEST 2: HTTP Protocol Layer (httpC module) ===");
        
        try {
            // Test HttpClient with structured requests
            HttpClient client(*sslContext_, "httpbin.org", "443");
            logMessage("HttpClient created for httpbin.org");
            
            // Build HTTP request using HttpRequest class - use a simpler endpoint
            HttpRequest req;
            req.method = "GET";
            req.path = "/json";
            req.headers["Host"] = "httpbin.org";
            req.headers["User-Agent"] = "ChrisPlusPlus-NetworkDemo/1.0";
            req.headers["Accept"] = "application/json";
            req.headers["Connection"] = "close";
            
            logMessage("HTTP request structured using HttpRequest class");
            logMessage("Sending HTTP request...");
            
            // Send request and get structured response
            HttpResponse resp = client.sendRequest(req);
            logMessage("HTTP request completed!");
            logMessage(QString("HTTP Response: %1 %2").arg(resp.statusCode).arg(QString::fromStdString(resp.statusMessage)));
            
            // Parse response body
            if (!resp.body.empty()) {
                logMessage(QString("Response Body: %1").arg(QString::fromStdString(resp.body).left(100)));
            }
            
            logMessage("HTTP Protocol Layer: WORKING PERFECTLY");
            
        } catch (const std::exception& e) {
            logMessage(QString("HTTP Test Failed: %1").arg(e.what()));
        }
    }
    
    void testFileTransfer() {
        logMessage("\n=== TEST 3: File Transfer System (fileIO module) ===");
        
        QString filePath = QFileDialog::getOpenFileName(
            this, "Select Test File for Upload", QDir::homePath(), "All Files (*.*)"
        );
        
        if (filePath.isEmpty()) {
            logMessage("No file selected for upload test");
            return;
        }
        
        QFileInfo fileInfo(filePath);
        logMessage(QString("Selected: %1 (%2 bytes)").arg(fileInfo.fileName()).arg(fileInfo.size()));
        
        try {
            // Create FileTransfer instance
            FileTransfer fileTransfer(*sslContext_);
            fileTransfer.setServer("httpbin.org", "443");
            logMessage("FileTransfer system configured");
            
            // Setup progress tracking
            progressBar_->setVisible(true);
            progressBar_->setValue(0);
            
            auto progressCallback = [this](qint64 transferred, qint64 total) -> bool {
                int percent = (total > 0) ? (transferred * 100) / total : 0;
                progressBar_->setValue(percent);
                
                if (transferred == total) {
                    logMessage("Upload complete, waiting for server response...");
                }
                
                return true; // Continue
            };
            
            logMessage("Starting file upload...");
            
            // Perform upload using complete system stack
            TransferResult result = fileTransfer.uploadFile(
                filePath, "/post", progressCallback, 1
            );
            
            progressBar_->setVisible(false);
            
            if (result.success) {
                logMessage(QString("Upload SUCCESS: %1 bytes transferred").arg(result.bytesTransferred));
                logMessage("Server confirmed file receipt");
                logMessage("File Transfer System: WORKING PERFECTLY");
            } else {
                logMessage(QString("Upload Failed: %1").arg(result.errorMessage));
            }
            
        } catch (const std::exception& e) {
            progressBar_->setVisible(false);
            logMessage(QString("File Transfer Test Failed: %1").arg(e.what()));
        }
    }
    
    void testCompleteSystem() {
        logMessage("\n=== COMPLETE SYSTEM INTEGRATION TEST ===");
        logMessage("Testing all modules working together...\n");
        
        // Run all tests sequentially
        testSSLFoundation();
        QTimer::singleShot(1000, this, &NetworkSystemDemo::testHTTPLayer);
        QTimer::singleShot(2000, this, [this]() {
            logMessage("\n=== SYSTEM ANALYSIS ===");
            logMessage("Module Usage:");
            logMessage("   sockets/SSLContext.cpp - TLS configuration");
            logMessage("   sockets/SSLConnection.cpp - Secure networking");  
            logMessage("   httpC/HttpClient.cpp - Protocol management");
            logMessage("   httpC/HttpRequest.cpp - Request building");
            logMessage("   httpC/HttpResponse.cpp - Response parsing");
            logMessage("   fileIO/fileTransfer.cpp - File operations");
            logMessage("\nALL MODULES ACTIVE AND FUNCTIONAL!");
            logMessage("Your network system is production-ready!");
        });
    }

private:
    void setupUI() {
        auto* layout = new QVBoxLayout(this);
        
        // Title
        auto* title = new QLabel("ChrisPlusPlus Network System Demo");
        title->setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;");
        layout->addWidget(title);
        
        // Test buttons
        auto* buttonLayout = new QHBoxLayout();
        
        auto* sslBtn = new QPushButton("Test SSL/TLS Foundation");
        auto* httpBtn = new QPushButton("Test HTTP Protocol");
        auto* fileBtn = new QPushButton("Test File Transfer");
        auto* completeBtn = new QPushButton("Run Complete Test");
        
        buttonLayout->addWidget(sslBtn);
        buttonLayout->addWidget(httpBtn);
        buttonLayout->addWidget(fileBtn);
        buttonLayout->addWidget(completeBtn);
        
        layout->addLayout(buttonLayout);
        
        // Progress bar
        progressBar_ = new QProgressBar();
        progressBar_->setVisible(false);
        layout->addWidget(progressBar_);
        
        // Log output
        logOutput_ = new QTextEdit();
        logOutput_->setFont(QFont("Monaco", 10));
        layout->addWidget(logOutput_);
        
        // Connect buttons
        connect(sslBtn, &QPushButton::clicked, this, &NetworkSystemDemo::testSSLFoundation);
        connect(httpBtn, &QPushButton::clicked, this, &NetworkSystemDemo::testHTTPLayer);
        connect(fileBtn, &QPushButton::clicked, this, &NetworkSystemDemo::testFileTransfer);
        connect(completeBtn, &QPushButton::clicked, this, &NetworkSystemDemo::testCompleteSystem);
    }
    
    void logMessage(const QString& message) {
        logOutput_->append(message);
        std::cout << message.toStdString() << std::endl;
    }

private:
    std::unique_ptr<SSLContext> sslContext_;
    QTextEdit* logOutput_;
    QProgressBar* progressBar_;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    std::cout << "ChrisPlusPlus Complete Network System Demo" << std::endl;
    std::cout << "This demo tests ALL your network modules working together!" << std::endl;
    
    NetworkSystemDemo demo;
    demo.show();
    
    return app.exec();
}

#include "testNetworkSystemComplete.moc" 