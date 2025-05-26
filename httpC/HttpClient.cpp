#include "HttpClient.h"
#include <QIODevice>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <map>

// 
HttpClient::HttpClient(SSLContext& ctx,
                       const std::string& host,
                       const std::string& port)
  : ctx_(ctx), host_(host), port_(port)
{}

HttpResponse HttpClient::sendRequest(const HttpRequest& req) {
    // 1) Open TLS connection
    SSLConnection conn(ctx_, host_, port_);

    // 2) Serialize & send
    auto rawReq = req.serialize();
    conn.send(rawReq.data(), rawReq.size());

    // 3) Use the same reliable response reading as streaming method
    return receiveResponse(conn);
}

HttpResponse HttpClient::sendRequestWithStreamingBody(const HttpRequest& req, QIODevice& bodySource) {
    // 1) Open TLS connection
    SSLConnection conn(ctx_, host_, port_);
    
    // 2) Send headers with chunked encoding
    HttpRequest streamingReq = req;
    streamingReq.headers["Transfer-Encoding"] = "chunked";
    streamingReq.body = ""; // No body in headers
    
    auto headerData = streamingReq.serialize();
    conn.send(headerData.data(), headerData.size());
    
    // 3) Send body in chunks
    if (!sendChunkedBody(conn, bodySource)) {
        throw std::runtime_error("Failed to send chunked body");
    }
    
    // 4) Receive response
    return receiveResponse(conn);
}

bool HttpClient::downloadToStream(const HttpRequest& req, QIODevice& destination) {
    // 1) Open TLS connection
    SSLConnection conn(ctx_, host_, port_);
    
    // 2) Send request
    auto rawReq = req.serialize();
    conn.send(rawReq.data(), rawReq.size());
    
    // 3) Stream response directly to destination
    return receiveResponseToStream(conn, destination);
}

bool HttpClient::sendChunkedBody(SSLConnection& conn, QIODevice& source) {
    const int CHUNK_SIZE = 8192; // 8KB chunks
    char buffer[CHUNK_SIZE];
    
    while (!source.atEnd()) {
        qint64 bytesRead = source.read(buffer, CHUNK_SIZE);
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
    std::cout << "Reading response with 10 second timeout..." << std::endl;
    
    // Set a short timeout for testing
    conn.setTimeout(10);
    
    std::string response;
    char buffer[4096];
    ssize_t totalBytes = 0;
    int attempts = 0;
    
    // Simple approach: read in chunks until we get nothing or timeout
    while (attempts < 10) { // Max 10 attempts
        ssize_t n = conn.receive(buffer, sizeof(buffer));
        
        if (n > 0) {
            response.append(buffer, n);
            totalBytes += n;
            std::cout << "Read chunk: " << n << " bytes (total: " << totalBytes << ")" << std::endl;
            
            // If we got a small chunk, probably done
            if (n < 1024) {
                std::cout << "Small chunk received, assuming response complete" << std::endl;
                break;
            }
        } else if (n == 0) {
            std::cout << "Connection closed by server" << std::endl;
            break;
        } else {
            std::cout << "Read error or timeout" << std::endl;
            break;
        }
        
        attempts++;
    }
    
    std::cout << "Response reading complete: " << response.size() << " bytes" << std::endl;
    
    if (response.empty()) {
        throw std::runtime_error("No response received");
    }
    
    return HttpResponse::parse(response);
}

void HttpClient::parseHeaders(const std::string& headers, 
                             std::string& statusLine, 
                             std::map<std::string, std::string>& headerMap) {
    std::istringstream stream(headers);
    std::getline(stream, statusLine);
    
    std::string line;
    while (std::getline(stream, line) && !line.empty() && line != "\r") {
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);
            
            // Trim whitespace and convert to lowercase
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t\r") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t\r") + 1);
            
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            headerMap[key] = value;
        }
    }
}

std::string HttpClient::readFixedLengthBody(SSLConnection& conn, int contentLength) {
    if (contentLength <= 0) return "";
    
    std::string body;
    body.reserve(contentLength);
    
    char buffer[8192];
    int totalRead = 0;
    
    while (totalRead < contentLength) {
        int toRead = std::min(sizeof(buffer), size_t(contentLength - totalRead));
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
        // Read chunk size line
        std::string chunkSizeLine;
        char buf[1];
        
        while (true) {
            ssize_t n = conn.receive(buf, 1);
            if (n <= 0) throw std::runtime_error("Connection closed reading chunk size");
            
            chunkSizeLine += buf[0];
            // Check for CRLF ending manually (compatible with older C++)
            if (chunkSizeLine.size() >= 2 && 
                chunkSizeLine.substr(chunkSizeLine.size() - 2) == "\r\n") {
                chunkSizeLine.pop_back(); // Remove \n
                chunkSizeLine.pop_back(); // Remove \r
                break;
            }
        }
        
        // Parse chunk size (hex)
        int chunkSize = std::stoi(chunkSizeLine, nullptr, 16);
        if (chunkSize == 0) {
            // Final chunk, read trailing headers/CRLF
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
    char buffer[8192];
    ssize_t n;
    
    while ((n = conn.receive(buffer, sizeof(buffer))) > 0) {
        body.append(buffer, n);
        
        // Safety: prevent memory exhaustion
        if (body.size() > 100 * 1024 * 1024) { // 100MB limit
            throw std::runtime_error("Response too large");
        }
    }
    
    return body;
}

bool HttpClient::receiveResponseToStream(SSLConnection& conn, QIODevice& destination) {
    // Read headers first
    std::string headers;
    char buf[1];
    std::string headerEnd = "\r\n\r\n";
    
    // Read until we find end of headers
    while (headers.find(headerEnd) == std::string::npos) {
        ssize_t n = conn.receive(buf, 1);
        if (n <= 0) return false;
        headers.append(buf, 1);
    }
    
    // Parse status code from headers
    std::istringstream headerStream(headers);
    std::string statusLine;
    std::getline(headerStream, statusLine);
    
    int statusCode = 0;
    std::istringstream statusStream(statusLine);
    std::string httpVersion;
    statusStream >> httpVersion >> statusCode;
    
    if (statusCode != 200) return false;
    
    // Stream body directly to destination
    char buffer[8192];
    ssize_t n;
    while ((n = conn.receive(buffer, sizeof(buffer))) > 0) {
        if (destination.write(buffer, n) != n) {
            return false; // Write failed
        }
    }
    
    return true;
}
