#pragma once
#include "HttpRequest.h"
#include "HttpResponse.h"
#include "../sockets/SSLContext.h"
#include "../sockets/SSLConnection.h"
#include <functional>
#include <QtConcurrent>

// Forward declaration instead of including QIODevice
class QIODevice;

/**
 * Low-level HTTPS client (blocking + async)
 * Thread-safe as long as each instance is used from one thread at a time.
 */

class HttpClient : public std::enable_shared_from_this<HttpClient> {
public:
    HttpClient(SSLContext& ctx,
               const std::string& host,
               const std::string& port = "443");

    
    //Blocking synchronous HTTP request
    HttpResponse sendRequest(const HttpRequest& req);

    //Asynchronous HTTP request (non-blocking - GUI safe)
    void sendAsync(const HttpRequest&  req,
               std::function<void (const HttpResponse&)> onSuccess,
               std::function<void (const QString&     )> onError);
    // Streaming methods
    HttpResponse sendRequestWithStreamingBody(const HttpRequest& req, QIODevice& bodySource);
    bool downloadToStream(const HttpRequest& req, QIODevice& destination);
    
    //streaming download with progress callback (blocking)
    bool downloadToStreamWithProgress(const HttpRequest& req, QIODevice& destination, 
                                     std::function<bool(qint64, qint64)> progressCallback);

    void setChunkSize(size_t size) { chunkSize_ = size; }
    size_t getChunkSize() const { return chunkSize_; }

    // NEW: Async methods for FileTransfer
    void downloadAsync(const HttpRequest& request,
                       const QString& filePath,
                       std::function<void(const HttpResponse&)> onSuccess, 
                       std::function<void(const QString&)> onError);

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
