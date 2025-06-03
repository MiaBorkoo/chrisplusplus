#pragma once
#include <string>
#include <map>

// represents an HTTP request, serializes it into the raw HTTP protocol format that servers understand
struct HttpRequest {
    std::string method;                      // e.g. "GET", "POST"
    std::string path;                        // e.g. "/api/files"
    std::map<std::string,std::string> headers;
    std::string body;                        // we can remove this if we don't need to send a body

    std::string serialize() const;           // builds the raw HTTP/1.1 request
};
