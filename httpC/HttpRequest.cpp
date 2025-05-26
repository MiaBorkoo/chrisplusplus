#include "HttpRequest.h"

std::string HttpRequest::serialize() const {
    std::string result = method + " " + path + " HTTP/1.1\r\n";
    
    // Add Host header if not present
    bool hasHost = false;
    for (const auto& header : headers) {
        result += header.first + ": " + header.second + "\r\n";
        if (header.first == "Host") hasHost = true;
    }
    
    // Add Content-Length for POST/PUT with body
    if (!body.empty() && headers.find("Content-Length") == headers.end()) {
        result += "Content-Length: " + std::to_string(body.length()) + "\r\n";
    }
    
    result += "\r\n";  // End headers
    result += body;    // Add body if present
    
    return result;
} 