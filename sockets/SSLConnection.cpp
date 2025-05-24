// implementation
#include "SSLConnection.h"
#include "SSLContext.h"

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>        // Add this for F_GETFL, F_SETFL
#include <sys/select.h>   // Add this for select()
#include <stdexcept>
#include <cstring>

SSLConnection::SSLConnection(SSLContext& ctx,
                             const std::string& host,
                             const std::string& port)
    : host_(host)
{
    // 1) TCP connect
    sockfd_ = connectTCP(host, port); //this is the socket file descriptor, "example.com" is the hostname, "443" is the port number

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
int SSLConnection::connectTCP(const std::string& host, //test calls this function with "example.com" and "443"
                              const std::string& port,
                              int timeout_seconds)
{
    struct addrinfo hints{}, *res, *rp;
    hints.ai_family   = AF_UNSPEC;     // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;   // TCP

    //hostname resolution (DNS)
    int err = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (err != 0) {
        throw std::runtime_error("getaddrinfo: " + std::string(gai_strerror(err)));
    }

    int sock = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol); //creates the actual socket 
        if (sock < 0) continue;
        
        //just accepted this whole part that implements blocking and non-blocking socket operations, LOOK INTO IT
        // Set non-blocking for timeout support
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        int result = ::connect(sock, rp->ai_addr, rp->ai_addrlen); //tcp connection to the server
        if (result == 0) {
            // Immediate connection
            fcntl(sock, F_SETFL, flags); // Restore blocking
            break;
        }
        
        if (errno == EINPROGRESS) {
            // Use select() for timeout handling
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);
            
            struct timeval tv = {timeout_seconds, 0};
            if (select(sock + 1, nullptr, &write_fds, nullptr, &tv) > 0) {
                fcntl(sock, F_SETFL, flags); // Restore blocking
                break;
            }
        }
        
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0) {
        throw std::runtime_error("Failed to connect TCP socket");
    }
    return sock; //returns the socket file descriptor
}

//certificate verification part 
void SSLConnection::verifyPeerCertificate()
{
    // A) Check chain validation result
    long verify_res = SSL_get_verify_result(ssl_);
    if (verify_res != X509_V_OK) {
        std::string error_msg = "Certificate verification failed: ";
        error_msg += X509_verify_cert_error_string(verify_res);
        throw std::runtime_error(error_msg);
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
