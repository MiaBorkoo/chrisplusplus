#include "HttpResponse.h"
#include "HttpClient.h"  // For extractFilenameFromContentDisposition
#include <sstream>

HttpResponse HttpResponse::parse(const std::string& raw) {
    HttpResponse response;
    std::istringstream stream(raw);
    std::string line;
    
    // Parse status line: "HTTP/1.1 200 OK"
    if (std::getline(stream, line)) {
        std::istringstream statusStream(line);
        std::string httpVersion;
        statusStream >> httpVersion >> response.statusCode;
        std::getline(statusStream, response.statusMessage);
        // Remove leading space and \r
        if (!response.statusMessage.empty() && response.statusMessage[0] == ' ') {
            response.statusMessage = response.statusMessage.substr(1);
        }
        if (!response.statusMessage.empty() && response.statusMessage.back() == '\r') {
            response.statusMessage.pop_back();
        }
    }
    
    // Parse headers
    while (std::getline(stream, line) && line != "\r" && !line.empty()) {
        if (line.back() == '\r') line.pop_back();  // Remove \r
        
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);
            // Trim leading space from value
            if (!value.empty() && value[0] == ' ') {
                value = value.substr(1);
            }
            response.headers[key] = value;
        }
    }
    
    // Extract filename from Content-Disposition header if present
    auto contentDispIt = response.headers.find("Content-Disposition");
    if (contentDispIt == response.headers.end()) {
        // Try lowercase version
        contentDispIt = response.headers.find("content-disposition");
    }
    if (contentDispIt != response.headers.end()) {
        response.filename = HttpClient::extractFilenameFromContentDisposition(contentDispIt->second);
    }
    
    // Parse body (rest of the stream)
    std::string bodyLine;
    while (std::getline(stream, bodyLine)) {
        response.body += bodyLine + "\n";
    }
    if (!response.body.empty() && response.body.back() == '\n') {
        response.body.pop_back();  // Remove trailing newline
    }
    
    return response;
} 