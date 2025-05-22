// implementation
#include "SSLConnection.h"
#include "SSLContext.h"

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <netdb.h>
#include <unistd.h>
#include <stdexcept>
#include <cstring>

SSLConnection::SSLConnection(SSLContext& ctx,
                             const std::string& host,
                             const std::string& port)
    : host_(host)
{
    // 1) TCP connect
    sockfd_ = connectTCP(host, port);

    // 2) Create SSL session
    ssl_ = SSL_new(ctx.get());
    if (!ssl_) {
        throw std::runtime_error("SSL_new() failed");
    }

    // 3) Set SNI (Server Name Indication)
    if (!SSL_set_tlsext_host_name(ssl_, host.c_str())) {
        throw std::runtime_error("Failed to set SNI hostname");
    }

    // 4) Attach socket FD to SSL
    SSL_set_fd(ssl_, sockfd_);

    // 5) Perform TLS handshake
    if (SSL_connect(ssl_) != 1) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        throw std::runtime_error(std::string("SSL_connect failed: ") + buf);
    }

    // 6) Verify certificate chain and hostname
    verifyPeerCertificate();
}

SSLConnection::~SSLConnection()
{
    if (ssl_) {
        SSL_shutdown(ssl_);  
        SSL_free(ssl_);
    }
    if (sockfd_ >= 0) {
        close(sockfd_);
    }
}

SSLConnection::SSLConnection(SSLConnection&& o) noexcept
  : sockfd_(o.sockfd_), ssl_(o.ssl_), host_(std::move(o.host_))
{
    o.sockfd_ = -1;
    o.ssl_    = nullptr;
}

SSLConnection& SSLConnection::operator=(SSLConnection&& o) noexcept
{
    if (this != &o) {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        if (sockfd_ >= 0) {
            close(sockfd_);
        }
        sockfd_ = o.sockfd_;
        ssl_    = o.ssl_;
        host_   = std::move(o.host_);
        o.sockfd_ = -1;
        o.ssl_    = nullptr;
    }
    return *this;
}

ssize_t SSLConnection::send(const void* data, size_t len)
{
    return SSL_write(ssl_, data, static_cast<int>(len));
}

ssize_t SSLConnection::receive(void* buf, size_t buflen)
{
    return SSL_read(ssl_, buf, static_cast<int>(buflen));
}

//this part is especially what mark taught us 
int SSLConnection::connectTCP(const std::string& host,
                              const std::string& port)
{
    struct addrinfo hints{}, *res, *rp;
    hints.ai_family   = AF_UNSPEC;     // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;   // TCP

    int err = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (err != 0) {
        throw std::runtime_error("getaddrinfo: " + std::string(gai_strerror(err)));
    }

    int sock = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        if (::connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
            break;  // success
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0) {
        throw std::runtime_error("Failed to connect TCP socket");
    }
    return sock;
}

//certificate verification part 
void SSLConnection::verifyPeerCertificate()
{
    // A) Check chain validation result
    long verify_res = SSL_get_verify_result(ssl_);
    if (verify_res != X509_V_OK) {
        throw std::runtime_error("Certificate chain validation failed");
    }

    // B) Check hostname against CN/SAN
    X509* cert = SSL_get_peer_certificate(ssl_);
    if (!cert) {
        throw std::runtime_error("No certificate presented by peer");
    }
    if (X509_check_host(cert, host_.c_str(), host_.size(), 0, nullptr) != 1) {
        X509_free(cert);
        throw std::runtime_error("Hostname mismatch in certificate");
    }
    
    X509_free(cert);
}
