#include "HttpClient.h"

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

    // 3) Read full response
    std::string rawResp;
    char buf[4096];
    ssize_t n;
    while ((n = conn.receive(buf, sizeof(buf))) > 0) {
        rawResp.append(buf, buf + n);
    }

    // 4) Parse & return
    return HttpResponse::parse(rawResp);
}
