#pragma once
#include "HttpRequest.h"
#include "HttpResponse.h"
#include "../sockets/SSLContext.h"
#include "../sockets/SSLConnection.h"

class HttpClient {
public:
    HttpClient(SSLContext& ctx,
               const std::string& host,
               const std::string& port = "443");

    HttpResponse sendRequest(const HttpRequest& req);

private:
    SSLContext& ctx_;
    std::string host_, port_;
};
