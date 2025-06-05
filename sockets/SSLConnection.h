// SSLConnection wrapper
#pragma once

#include <openssl/ssl.h>
#include <string>
#include <functional>

//manages a single TLS connection: DNS → TCP → TLS handshake → certificate & hostname verification → encrypted I/O.
class SSLConnection {

public:
    //constructor for the SSLConnection class
    //param ctx   Your SSLContext (holds configured SSL_CTX*)
    //param host  Server hostname (for SNI & cert checks)
    //param port  Service port (e.g. "443")
    //throws std::runtime_error on any failure (DNS, TCP, TLS, cert check)

    // Regular constructor
    SSLConnection(class SSLContext& ctx,
                  const std::string& host,
                  const std::string& port);

    ~SSLConnection();

    // No copies (sockets and SSL* can't be shared safely)
    SSLConnection(const SSLConnection&) = delete;
    SSLConnection& operator=(const SSLConnection&) = delete;

    // Move constructor (different parameter signature)
    SSLConnection(SSLConnection&& other) noexcept;
    SSLConnection& operator=(SSLConnection&& other) noexcept;

    //send the data over the TLS channel
    ssize_t send(const void* data, size_t len);

    //receive the data over the TLS channel
    ssize_t receive(void* buf, size_t buflen);

    void setTimeout(int seconds);
    
    // Socket optimization for file transfers
    void optimizeForFileTransfer();
    void setSocketBufferSizes(int sendBuffer, int receiveBuffer);
    void enableTcpNoDelay(bool enable = true);

    // Advanced streaming with progress and cancellation
    ssize_t sendWithProgress(const void* data, size_t len, 
                            std::function<bool(size_t)> progressCallback = nullptr);
    ssize_t receiveWithProgress(void* buf, size_t buflen,
                               std::function<bool(size_t)> progressCallback = nullptr);
    
    // Bulk streaming operations
    bool streamFromSource(std::function<ssize_t(void*, size_t)> reader,
                         std::function<bool(size_t, size_t)> progressCallback = nullptr);
    bool streamToDestination(std::function<ssize_t(const void*, size_t)> writer,
                            size_t expectedBytes = 0,
                            std::function<bool(size_t, size_t)> progressCallback = nullptr);

private:
    //resolve the host to a socket file descriptor
    int connectTCP(const std::string& host, 
                   const std::string& port, 
                   int timeout_seconds = 30);  // Add default parameter

    //after the SSL_connect(), verify the chain and hostname match
    void verifyPeerCertificate();

    int      sockfd_{-1};    //underlying TCP socket file descriptor
    SSL*     ssl_{nullptr};  //OpenSSL session object
    std::string host_;       //hostname for SNI & cert checks
    int timeoutSeconds_{30};
};
