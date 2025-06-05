// implementation
#include "SSLConnection.h"
#include "SSLContext.h"

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>        // Add this for F_GETFL, F_SETFL
#include <sys/select.h>   // Add this for select()
#include <netinet/tcp.h>  // Add this for TCP_NODELAY
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <functional>

SSLConnection::SSLConnection(SSLContext& ctx,
                             const std::string& host,
                             const std::string& port)
    : host_(host)
{
    // 1) TCP connect
    std::cout << "Attempting TCP connection to " << host << ":" << port << std::endl;
    sockfd_ = connectTCP(host, port); //this is the socket file descriptor, "example.com" is the hostname, "443" is the port number
    std::cout << "TCP connection successful, socket fd: " << sockfd_ << std::endl;

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
    std::cout << "Starting SSL handshake..." << std::endl;

    // Set socket to non-blocking for timeout control
    int flags = fcntl(sockfd_, F_GETFL, 0);
    fcntl(sockfd_, F_SETFL, flags | O_NONBLOCK);

    // 5) Perform TLS handshake with timeout
    int ssl_result;
    int max_attempts = 30; // 30 second timeout
    int attempts = 0;
    
    while (attempts < max_attempts) {
        ssl_result = SSL_connect(ssl_);
        
        if (ssl_result == 1) {
            // Success!
            break;
        }
        
        int ssl_error = SSL_get_error(ssl_, ssl_result);
        
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            // Need to wait for socket to be ready
            fd_set read_fds, write_fds;
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            
            if (ssl_error == SSL_ERROR_WANT_READ) {
                FD_SET(sockfd_, &read_fds);
            } else {
                FD_SET(sockfd_, &write_fds);
            }
            
            struct timeval tv = {1, 0}; // 1 second timeout per attempt
            int select_result = select(sockfd_ + 1, &read_fds, &write_fds, nullptr, &tv);
            
            if (select_result > 0) {
                // Socket is ready, try again
                attempts++;
                continue;
            } else if (select_result == 0) {
                // Timeout
                attempts++;
                std::cout << "SSL handshake attempt " << attempts << "/" << max_attempts << std::endl;
                continue;
            } else {
                // select() error
                throw std::runtime_error("select() failed during SSL handshake");
            }
        } else {
            // Actual SSL error
            break;
        }
    }
    
    // Restore blocking mode
    fcntl(sockfd_, F_SETFL, flags);
    
    if (ssl_result != 1) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        
        // Get more detailed error information
        int ssl_error = SSL_get_error(ssl_, ssl_result);
        std::string detailed_error = "SSL_connect failed after " + std::to_string(attempts) + " attempts: ";
        detailed_error += buf;
        detailed_error += " (SSL error code: " + std::to_string(ssl_error) + ")";
        
        // Print all errors in the queue
        std::cout << "SSL Error Details:" << std::endl;
        while ((err = ERR_get_error()) != 0) {
            ERR_error_string_n(err, buf, sizeof(buf));
            std::cout << "  " << buf << std::endl;
        }
        
        throw std::runtime_error(detailed_error);
    }
    
    std::cout << "SSL handshake successful!" << std::endl;

    // 6) Only verify certificate if verification is enabled in the context
    int verify_mode = SSL_CTX_get_verify_mode(ctx.get());
    if (verify_mode != SSL_VERIFY_NONE) {
        verifyPeerCertificate();
    } else {
        std::cout << "Skipping certificate verification (SSL_VERIFY_NONE)" << std::endl;
    }
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

void SSLConnection::setTimeout(int seconds) {
    timeoutSeconds_ = seconds;
    // Apply to existing socket if connected
    if (sockfd_ >= 0) {
        struct timeval tv = {seconds, 0};
        setsockopt(sockfd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sockfd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
}

void SSLConnection::optimizeForFileTransfer() {
    if (sockfd_ < 0) return;
    
    // Optimize for large file transfers
    setSocketBufferSizes(256 * 1024, 256 * 1024); // 256KB buffers
    enableTcpNoDelay(true);  // Disable Nagle's algorithm for streaming
    
    // Set keep-alive for long transfers
    int keepalive = 1;
    setsockopt(sockfd_, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    
    std::cout << "Socket optimized for file transfer" << std::endl;
}

void SSLConnection::setSocketBufferSizes(int sendBuffer, int receiveBuffer) {
    if (sockfd_ < 0) return;
    
    if (setsockopt(sockfd_, SOL_SOCKET, SO_SNDBUF, &sendBuffer, sizeof(sendBuffer)) == 0) {
        std::cout << "Send buffer set to " << sendBuffer << " bytes" << std::endl;
    }
    
    if (setsockopt(sockfd_, SOL_SOCKET, SO_RCVBUF, &receiveBuffer, sizeof(receiveBuffer)) == 0) {
        std::cout << "Receive buffer set to " << receiveBuffer << " bytes" << std::endl;
    }
}

void SSLConnection::enableTcpNoDelay(bool enable) {
    if (sockfd_ < 0) return;
    
    int flag = enable ? 1 : 0;
    if (setsockopt(sockfd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) == 0) {
        std::cout << "TCP_NODELAY " << (enable ? "enabled" : "disabled") << std::endl;
    }
}

ssize_t SSLConnection::sendWithProgress(const void* data, size_t len, 
                                       std::function<bool(size_t)> progressCallback) {
    ssize_t result = SSL_write(ssl_, data, static_cast<int>(len));
    if (result > 0 && progressCallback) {
        if (!progressCallback(result)) {
            return -1; // Signal cancellation
        }
    }
    return result;
}

ssize_t SSLConnection::receiveWithProgress(void* buf, size_t buflen,
                                         std::function<bool(size_t)> progressCallback) {
    ssize_t result = SSL_read(ssl_, buf, static_cast<int>(buflen));
    if (result > 0 && progressCallback) {
        if (!progressCallback(result)) {
            return -1; // Signal cancellation
        }
    }
    return result;
}

bool SSLConnection::streamFromSource(std::function<ssize_t(void*, size_t)> reader,
                                   std::function<bool(size_t, size_t)> progressCallback) {
    const size_t BUFFER_SIZE = 128 * 1024; // 128KB chunks
    char buffer[BUFFER_SIZE];
    size_t totalSent = 0;
    
    while (true) {
        // Read from source
        ssize_t bytesRead = reader(buffer, BUFFER_SIZE);
        if (bytesRead <= 0) break; // EOF or error
        
        // Send via SSL
        ssize_t bytesSent = 0;
        while (bytesSent < bytesRead) {
            ssize_t sent = SSL_write(ssl_, buffer + bytesSent, bytesRead - bytesSent);
            if (sent <= 0) return false;
            bytesSent += sent;
        }
        
        totalSent += bytesRead;
        
        // Progress callback
        if (progressCallback && !progressCallback(totalSent, 0)) {
            return false; // Cancelled
        }
    }
    
    return true;
}

bool SSLConnection::streamToDestination(std::function<ssize_t(const void*, size_t)> writer,
                                      size_t expectedBytes,
                                      std::function<bool(size_t, size_t)> progressCallback) {
    const size_t BUFFER_SIZE = 128 * 1024; // 128KB chunks
    char buffer[BUFFER_SIZE];
    size_t totalReceived = 0;
    
    while (expectedBytes == 0 || totalReceived < expectedBytes) {
        size_t toRead = BUFFER_SIZE;
        if (expectedBytes > 0) {
            toRead = std::min(BUFFER_SIZE, expectedBytes - totalReceived);
        }
        
        // Receive via SSL
        ssize_t bytesReceived = SSL_read(ssl_, buffer, toRead);
        if (bytesReceived <= 0) {
            if (expectedBytes == 0) break; // EOF for unknown length
            return false; // Error for known length
        }
        
        // Write to destination
        if (writer(buffer, bytesReceived) != bytesReceived) {
            return false;
        }
        
        totalReceived += bytesReceived;
        
        // Progress callback
        if (progressCallback && !progressCallback(totalReceived, expectedBytes)) {
            return false; // Cancelled
        }
    }
    
    return true;
}
