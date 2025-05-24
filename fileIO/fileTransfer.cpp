#include "fileTransfer.h"
#include <QFile>

/**
 * @file fileTransfer.cpp
 * @brief Implements the FileTransfer class methods.
 *
 * uploadFile:
 *   - Opens the file at `localPath` as a QIODevice
 *   - Streams it in chunks over an HTTP POST with chunked encoding
 * 
 * downloadFile:
 *   - Issues an HTTP GET and writes incoming chunks directly
 *     to a QFile at `destPath`
 *
 * All network I/O goes over the injected HttpClient, which enforces
 * SSL/TLS with certificate and hostname verification.
 */


FileTransfer::FileTransfer(HttpClient& client)
  : httpClient_(client)
{}

bool FileTransfer::uploadFile(const QString& localPath, const QUrl& uploadUrl) {
    QFile file(localPath);
    if (!file.open(QIODevice::ReadOnly)) return false;

    // Read file in chunks and build body string
    QByteArray fileData = file.readAll();
    
    HttpRequest req;
    req.method = "POST";
    req.path = uploadUrl.path().toStdString();
    req.headers["Host"] = uploadUrl.host().toStdString();
    req.headers["Content-Type"] = "application/octet-stream";
    req.body = fileData.toStdString();
    
    HttpResponse resp = httpClient_.sendRequest(req);
    
    file.close();
    return (resp.statusCode == 200);
}

bool FileTransfer::downloadFile(const QUrl& downloadUrl, const QString& destPath) {
    QFile outFile(destPath);
    if (!outFile.open(QIODevice::WriteOnly)) return false;

    HttpRequest req;
    req.method = "GET";
    req.path = downloadUrl.path().toStdString();
    req.headers["Host"] = downloadUrl.host().toStdString();
    req.headers["Connection"] = "close";
    
    HttpResponse resp = httpClient_.sendRequest(req);
    
    // Write response body to file
    if (resp.statusCode == 200) {
        outFile.write(resp.body.c_str(), resp.body.size());
    }
    
    outFile.close();
    return (resp.statusCode == 200);
}
