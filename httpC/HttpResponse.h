#pragma once
#include <string>
#include <map>

// parses raw HTTP responses from servers into structured data
struct HttpResponse {
    int statusCode;                          // e.g. 200
    std::string statusMessage;               // e.g. "OK"
    std::map<std::string,std::string> headers;
    std::string body;
    std::string filename;                    // Extracted from Content-Disposition header

    static HttpResponse parse(const std::string& raw);  // parse raw HTTP response
};
