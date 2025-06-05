#include "HttpClient.h"
#include <QIODevice>
#include <QThreadPool>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <map>

HttpClient::HttpClient(SSLContext& ctx,
                       const std::string& host,
                       const std::string& port)
  : ctx_(ctx), host_(host), port_(port)
{}

//Blocking synchronous HTTP request
HttpResponse HttpClient::sendRequest(const HttpRequest& req) {
    try {
        // 1) Open TLS connection
        std::cout << "HttpClient: Attempting SSL connection to " << host_ << ":" << port_ << std::endl;
        SSLConnection conn(ctx_, host_, port_);
        conn.setTimeout(30); // Set reasonable timeout

        // 2) Serialize & send
        auto rawReq = req.serialize();
        conn.send(rawReq.data(), rawReq.size());

        // 3) Use proper HTTP response reading
        return receiveResponse(conn);
    } catch (const std::exception& e) {
        std::cout << "HttpClient: SSL connection failed: " << e.what() << std::endl;
        
        // Return an error response instead of crashing
        HttpResponse errorResponse;
        errorResponse.statusCode = 0; // Connection error
        errorResponse.statusMessage = "Connection Failed";
        errorResponse.body = std::string("SSL connection failed: ") + e.what();
        return errorResponse;
    }
}

//Asynchronous HTTP request (non-blocking - GUI safe)
void HttpClient::sendAsync(const HttpRequest& req,
                          std::function<void(const HttpResponse&)> onSuccess,
                          std::function<void(const QString&)> onError) {
    // RESTORE: Your original ACTUALLY async code
    auto self = shared_from_this();
    QThreadPool::globalInstance()->start([self, req, onSuccess, onError]{
        try {
            HttpResponse r = self->sendRequest(req);
            QMetaObject::invokeMethod(qApp, [onSuccess, r]{
                onSuccess(r);
            }, Qt::QueuedConnection);
        } catch (const std::exception& ex) {
            QMetaObject::invokeMethod(qApp, [onError, ex]{
                onError(QString::fromUtf8(ex.what()));
            }, Qt::QueuedConnection);
        }
    });
}

//streaming upload (blocking)
HttpResponse HttpClient::sendRequestWithStreamingBody(const HttpRequest& req, QIODevice& bodySource) {
    try {
        // 1) Open TLS connection
        std::cout << "HttpClient: Attempting SSL connection for streaming upload to " << host_ << ":" << port_ << std::endl;
        SSLConnection conn(ctx_, host_, port_);
        conn.setTimeout(60); // Longer timeout for uploads
        conn.optimizeForFileTransfer(); // NEW: Socket-level optimization
        
        // 2) Send headers with chunked encoding
        HttpRequest streamingReq = req;
        streamingReq.headers["Transfer-Encoding"] = "chunked";
        streamingReq.body = ""; // No body in headers
        
        auto headerData = streamingReq.serialize();
        conn.send(headerData.data(), headerData.size());
        
        // 3) Send body in chunks (HTTP chunked encoding required)
        if (!sendChunkedBody(conn, bodySource)) {
            throw std::runtime_error("Failed to send chunked body");
        }
        
        // 4) Receive response with proper HTTP parsing
        return receiveResponse(conn);
    } catch (const std::exception& e) {
        std::cout << "HttpClient: SSL connection failed for streaming upload: " << e.what() << std::endl;
        
        // Return an error response instead of crashing
        HttpResponse errorResponse;
        errorResponse.statusCode = 0; // Connection error
        errorResponse.statusMessage = "Connection Failed";
        errorResponse.body = std::string("SSL connection failed: ") + e.what();
        return errorResponse;
    }
}

//streaming download (blocking)
bool HttpClient::downloadToStream(const HttpRequest& req, QIODevice& destination) {
    try {
        // 1) Open TLS connection
        std::cout << "HttpClient: Attempting SSL connection for streaming download to " << host_ << ":" << port_ << std::endl;
        SSLConnection conn(ctx_, host_, port_);
        conn.setTimeout(60); // Longer timeout for downloads
        
        // 2) Send request
        auto rawReq = req.serialize();
        conn.send(rawReq.data(), rawReq.size());
        
        // 3) Stream response directly to destination
        return receiveResponseToStream(conn, destination);
    } catch (const std::exception& e) {
        std::cout << "HttpClient: SSL connection failed for streaming download: " << e.what() << std::endl;
        return false;
    }
}

bool HttpClient::sendChunkedBody(SSLConnection& conn, QIODevice& source) {
    const int CHUNK_SIZE = 128 * 1024; // Your 128KB chunks
    char buffer[CHUNK_SIZE];
    
    while (!source.atEnd()) {
        qint64 bytesRead = source.read(buffer, CHUNK_SIZE); // QIODevice::read()
        if (bytesRead <= 0) break;
        
        // Send chunk size in hex + CRLF
        std::ostringstream chunkHeader;
        chunkHeader << std::hex << bytesRead << "\r\n";
        std::string headerStr = chunkHeader.str();
        
        if (conn.send(headerStr.data(), headerStr.size()) <= 0) return false;
        
        // Send chunk data + CRLF
        if (conn.send(buffer, bytesRead) <= 0) return false;
        if (conn.send("\r\n", 2) <= 0) return false;
    }
    
    // Send final chunk (0-length)
    if (conn.send("0\r\n\r\n", 5) <= 0) return false;
    return true;
}

HttpResponse HttpClient::receiveResponse(SSLConnection& conn) {
    // STEP 1: Read headers until we find "\r\n\r\n"
    std::string headers;
    std::string headerEnd = "\r\n\r\n";
    char buf[1];
    
    while (headers.find(headerEnd) == std::string::npos) {
        ssize_t n = conn.receive(buf, 1);
        if (n <= 0) throw std::runtime_error("Failed to read headers");
        headers.append(buf, 1);
        
        // Safety check to prevent memory exhaustion
        if (headers.size() > 64 * 1024) { // 64KB header limit
            throw std::runtime_error("Headers too large");
        }
    }
    
    // STEP 2: Parse headers to understand how to read body
    std::string statusLine;
    std::map<std::string, std::string> headerMap;
    parseHeaders(headers, statusLine, headerMap);
    
    // STEP 3: Read body based on HTTP headers
    std::string body;
    auto contentLengthIt = headerMap.find("content-length");
    auto transferEncodingIt = headerMap.find("transfer-encoding");
    
    if (transferEncodingIt != headerMap.end() && 
        transferEncodingIt->second.find("chunked") != std::string::npos) {
        // Chunked transfer encoding
        body = readChunkedBody(conn);
    } else if (contentLengthIt != headerMap.end()) {
        // Fixed content length
        int contentLength = std::stoi(contentLengthIt->second);
        body = readFixedLengthBody(conn, contentLength);
    } else {
        // Read until connection closes (HTTP/1.0 style)
        body = readUntilClose(conn);
    }
    
    // STEP 4: Parse complete HTTP response
    return HttpResponse::parse(headers + body);
}

void HttpClient::parseHeaders(const std::string& headers, 
                             std::string& statusLine, 
                             std::map<std::string, std::string>& headerMap) {
    std::istringstream stream(headers);
    std::getline(stream, statusLine);
    
    // Remove \r from status line if present
    if (!statusLine.empty() && statusLine.back() == '\r') {
        statusLine.pop_back();
    }
    
    std::string line;
    while (std::getline(stream, line) && !line.empty() && line != "\r") {
        // Remove \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);
            
            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            // Convert key to lowercase for case-insensitive lookup
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            headerMap[key] = value;
        }
    }
}

std::string HttpClient::readFixedLengthBody(SSLConnection& conn, int contentLength) {
    if (contentLength <= 0) return "";
    
    std::string body;
    body.reserve(contentLength);
    
    // OPTIMIZED: 128KB buffer for downloads
    const int BUFFER_SIZE = 128 * 1024; // 128KB
    char buffer[BUFFER_SIZE];
    int totalRead = 0;
    
    while (totalRead < contentLength) {
        int toRead = std::min(BUFFER_SIZE, contentLength - totalRead);
        ssize_t n = conn.receive(buffer, toRead);
        
        if (n <= 0) {
            throw std::runtime_error("Connection closed while reading body");
        }
        
        body.append(buffer, n);
        totalRead += n;
    }
    
    return body;
}

std::string HttpClient::readChunkedBody(SSLConnection& conn) {
    std::string body;
    
    while (true) {
        // Read chunk size line (hex number followed by \r\n)
        std::string chunkSizeLine;
        char buf[1];
        
        while (true) {
            ssize_t n = conn.receive(buf, 1);
            if (n <= 0) throw std::runtime_error("Connection closed reading chunk size");
            
            chunkSizeLine += buf[0];
            // Look for \r\n ending
            if (chunkSizeLine.size() >= 2 && 
                chunkSizeLine.substr(chunkSizeLine.size() - 2) == "\r\n") {
                chunkSizeLine.pop_back(); // Remove \n
                chunkSizeLine.pop_back(); // Remove \r
                break;
            }
        }
        
        // Parse chunk size (hex format)
        int chunkSize;
        std::istringstream hexStream(chunkSizeLine);
        hexStream >> std::hex >> chunkSize;
        
        if (chunkSize == 0) {
            // Final chunk - read any trailing headers and final \r\n
            std::string trailer;
            while (trailer.size() < 2 || trailer.substr(trailer.size() - 2) != "\r\n") {
                ssize_t n = conn.receive(buf, 1);
                if (n <= 0) break;
                trailer += buf[0];
            }
            break;
        }
        
        // Read chunk data
        std::string chunk = readFixedLengthBody(conn, chunkSize);
        body += chunk;
        
        // Read trailing CRLF after chunk
        conn.receive(buf, 1); // \r
        conn.receive(buf, 1); // \n
    }
    
    return body;
}

std::string HttpClient::readUntilClose(SSLConnection& conn) {
    std::string body;
    // OPTIMIZED: 128KB buffer
    const int BUFFER_SIZE = 128 * 1024;
    char buffer[BUFFER_SIZE];
    ssize_t n;
    
    while ((n = conn.receive(buffer, BUFFER_SIZE)) > 0) {
        body.append(buffer, n);
        
        // Safety: prevent memory exhaustion
        if (body.size() > 100 * 1024 * 1024) { // 100MB limit
            throw std::runtime_error("Response too large");
        }
    }
    
    return body;
}

bool HttpClient::receiveResponseToStream(SSLConnection& conn, QIODevice& destination) {
    // Read headers until "\r\n\r\n"
    std::string headers;
    char buf[1];
    std::string headerEnd = "\r\n\r\n";
    
    while (headers.find(headerEnd) == std::string::npos) {
        ssize_t n = conn.receive(buf, 1);
        if (n <= 0) return false;
        headers.append(buf, 1);
    }
    
    // Parse headers properly
    std::string statusLine;
    std::map<std::string, std::string> headerMap;
    parseHeaders(headers, statusLine, headerMap);
    
    // Extract status code
    int statusCode = 0;
    std::istringstream statusStream(statusLine);
    std::string httpVersion;
    statusStream >> httpVersion >> statusCode;
    
    if (statusCode != 200) return false;
    
    // CRITICAL FIX: Read based on Content-Length
    auto contentLengthIt = headerMap.find("content-length");
    if (contentLengthIt != headerMap.end()) {
        int contentLength = std::stoi(contentLengthIt->second);
        
        // Read exactly contentLength bytes
        const int BUFFER_SIZE = 128 * 1024;
        char buffer[BUFFER_SIZE];
        int totalRead = 0;
        
        while (totalRead < contentLength) {
            int toRead = std::min(BUFFER_SIZE, contentLength - totalRead);
            ssize_t n = conn.receive(buffer, toRead);
            
            if (n <= 0) return false;
            if (destination.write(buffer, n) != n) return false;
            
            totalRead += n;
        }
        
        return true;
    }
    
    // Fallback: read until close
    const int BUFFER_SIZE = 128 * 1024;
    char buffer[BUFFER_SIZE];
    ssize_t n;
    while ((n = conn.receive(buffer, BUFFER_SIZE)) > 0) {
        if (destination.write(buffer, n) != n) return false;
    }
    
    return true;
}

bool HttpClient::downloadToStreamWithProgress(const HttpRequest& req, QIODevice& destination,
                                             std::function<bool(qint64, qint64)> progressCallback) {
    // 1) Open TLS connection
    SSLConnection conn(ctx_, host_, port_);
    conn.setTimeout(60); // Longer timeout for downloads
    conn.optimizeForFileTransfer(); // NEW: Socket-level optimization
    
    // 2) Send request
    auto rawReq = req.serialize();
    conn.send(rawReq.data(), rawReq.size());
    
    // 3) Read headers until "\r\n\r\n"
    std::string headers;
    char buf[1];
    std::string headerEnd = "\r\n\r\n";
    
    while (headers.find(headerEnd) == std::string::npos) {
        ssize_t n = conn.receive(buf, 1);
        if (n <= 0) return false;
        headers.append(buf, 1);
    }
    
    // 4) Parse headers properly
    std::string statusLine;
    std::map<std::string, std::string> headerMap;
    parseHeaders(headers, statusLine, headerMap);
    
    // Extract status code
    int statusCode = 0;
    std::istringstream statusStream(statusLine);
    std::string httpVersion;
    statusStream >> httpVersion >> statusCode;
    
    if (statusCode != 200) return false;
    
    // 5) Get content length for progress tracking
    qint64 totalBytes = -1;
    auto contentLengthIt = headerMap.find("content-length");
    if (contentLengthIt != headerMap.end()) {
        totalBytes = std::stoll(contentLengthIt->second);
    }
    
    // 6) Stream with progress tracking
    const int BUFFER_SIZE = 128 * 1024;
    char buffer[BUFFER_SIZE];
    qint64 totalRead = 0;
    
    if (totalBytes > 0) {
        // Known content length - read exactly that amount
        while (totalRead < totalBytes) {
            int toRead = std::min(BUFFER_SIZE, static_cast<int>(totalBytes - totalRead));
            ssize_t n = conn.receive(buffer, toRead);
            
            if (n <= 0) return false;
            if (destination.write(buffer, n) != n) return false;
            
            totalRead += n;
            
            // Call progress callback
            if (progressCallback && !progressCallback(totalRead, totalBytes)) {
                return false; // User cancelled
            }
        }
    } else {
        // Unknown content length - read until close
        ssize_t n;
        while ((n = conn.receive(buffer, BUFFER_SIZE)) > 0) {
            if (destination.write(buffer, n) != n) return false;
            totalRead += n;
            
            // Call progress callback with unknown total
            if (progressCallback && !progressCallback(totalRead, -1)) {
                return false; // User cancelled
            }
        }
    }
    
    return true;
}

void HttpClient::downloadAsync(const HttpRequest& request,
                              const QString& filePath,
                              std::function<void(const HttpResponse&)> onSuccess,
                              std::function<void(const QString&)> onError) {
    
    auto self = shared_from_this();
    QThreadPool::globalInstance()->start([self, request, filePath, onSuccess, onError]{
        try {
            // Open file for streaming
            QFile file(filePath);
            if (!file.open(QIODevice::WriteOnly)) {
                QMetaObject::invokeMethod(qApp, [onError, filePath]{
                    onError("Cannot create file: " + filePath);
                }, Qt::QueuedConnection);
                return;
            }
            
            // Use streaming download
            bool success = self->downloadToStream(request, file);
            file.close();
            
            if (success) {
                // Create a fake response for the callback
                HttpResponse response;
                response.statusCode = 200;
                response.statusMessage = "OK";
                response.body = ""; // Body is in file, not memory
                
                QMetaObject::invokeMethod(qApp, [onSuccess, response]{
                    onSuccess(response);
                }, Qt::QueuedConnection);
            } else {
                QMetaObject::invokeMethod(qApp, [onError]{
                    onError("Streaming download failed");
                }, Qt::QueuedConnection);
            }
            
        } catch (const std::exception& e) {
            QMetaObject::invokeMethod(qApp, [onError, e]{
                onError(QString::fromStdString(e.what()));
            }, Qt::QueuedConnection);
        }
    });
}
