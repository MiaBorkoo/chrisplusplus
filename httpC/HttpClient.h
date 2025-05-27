#pragma once
#include "HttpRequest.h"
#include "HttpResponse.h"
#include "../sockets/SSLContext.h"
#include "../sockets/SSLConnection.h"

// Forward declaration instead of including QIODevice
class QIODevice;

//
class HttpClient {
public:
    HttpClient(SSLContext& ctx,
               const std::string& host,
               const std::string& port = "443");

    HttpResponse sendRequest(const HttpRequest& req);
    
    // Streaming methods
    HttpResponse sendRequestWithStreamingBody(const HttpRequest& req, QIODevice& bodySource);
    bool downloadToStream(const HttpRequest& req, QIODevice& destination);

    void setChunkSize(size_t size) { chunkSize_ = size; }
    size_t getChunkSize() const { return chunkSize_; }

private:
    SSLContext& ctx_;
    std::string host_, port_;
    size_t chunkSize_{128 * 1024}; // Default 128KB
    
    // Helper methods
    bool sendChunkedBody(SSLConnection& conn, QIODevice& source);
    HttpResponse receiveResponse(SSLConnection& conn);
    bool receiveResponseToStream(SSLConnection& conn, QIODevice& destination);
    void parseHeaders(const std::string& headers, 
                     std::string& statusLine, 
                     std::map<std::string, std::string>& headerMap);
    std::string readFixedLengthBody(SSLConnection& conn, int contentLength);
    std::string readChunkedBody(SSLConnection& conn);
    std::string readUntilClose(SSLConnection& conn);
};
