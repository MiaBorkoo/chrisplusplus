#pragma once
#include <string>
#include <map>

struct HttpRequest {
    std::string method;                      // e.g. "GET", "POST"
    std::string path;                        // e.g. "/api/files"
    std::map<std::string,std::string> headers;
    std::string body;                        // optional

    std::string serialize() const;           // builds the raw HTTP/1.1 request
};
