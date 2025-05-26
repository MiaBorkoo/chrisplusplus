// SSLConnection wrapper
#pragma once

#include <openssl/ssl.h>
#include <string>

//manages a single TLS connection: DNS → TCP → TLS handshake → certificate & hostname verification → encrypted I/O.
class SSLConnection {

public:
    //constructor for the SSLConnection class
    //param ctx   Your SSLContext (holds configured SSL_CTX*)
    //param host  Server hostname (for SNI & cert checks)
    //param port  Service port (e.g. "443")
    //throws std::runtime_error on any failure (DNS, TCP, TLS, cert check)

    //constructor for the SSLConnection class
    SSLConnection(class SSLContext& ctx,
                  const std::string& host,
                  const std::string& port);

    ~SSLConnection();

    // No copies (sockets and SSL* can’t be shared safely)
    SSLConnection(const SSLConnection&) = delete;
    SSLConnection& operator=(const SSLConnection&) = delete;

    // Allow move semantics (for containers/factories)
    SSLConnection(SSLConnection&& other) noexcept;
    SSLConnection& operator=(SSLConnection&& other) noexcept;

    //send the data over the TLS channel
    ssize_t send(const void* data, size_t len);

    //receive the data over the TLS channel
    ssize_t receive(void* buf, size_t buflen);

private:
    //resolve the host to a socket file descriptor
    int connectTCP(const std::string& host, const std::string& port);

    //after the SSL_connect(), verify the chain and hostname match
    void verifyPeerCertificate();

    int      sockfd_{-1};    //underlying TCP socket file descriptor
    SSL*     ssl_{nullptr};  //OpenSSL session object
    std::string host_;       //hostname for SNI & cert checks
};
