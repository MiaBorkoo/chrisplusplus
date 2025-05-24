#pragma once
#include <string>
#include <map>

struct HttpResponse {
    int statusCode;                          // e.g. 200
    std::string statusMessage;               // e.g. "OK"
    std::map<std::string,std::string> headers;
    std::string body;

    static HttpResponse parse(const std::string& raw);  // parse raw HTTP response
};
