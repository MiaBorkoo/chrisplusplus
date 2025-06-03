// implementation
#include "SSLContext.h"
#include <openssl/err.h>
#include <stdexcept>
#include <iostream>

//this is the initialization of the ssl context
void SSLContext::initializeOpenSSL()
{
    // these come from the openssl library
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSLContext::SSLContext()
    : ctx_(nullptr)
{
    // 1) Pick the client method (supports TLS 1.2+ - so we dont go back to the old versions of SSL)
    const SSL_METHOD* method = TLS_client_method();
    if (!method) {
        throw std::runtime_error("Unable to create TLS_client_method()");
    }

    // 2) Create the context
    ctx_ = SSL_CTX_new(method);
    if (!ctx_) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL_CTX_new() failed");
    }

    // 3) Enforce strong protocols & disable old ones - basically we are setting the minimum version of the protocol to TLS 1.2 like in step 1
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx_,
        SSL_OP_NO_SSLv2 |
        SSL_OP_NO_SSLv3 |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_CIPHER_SERVER_PREFERENCE
    ); //probs a shorter way to do this, will look into it later

    // 4) Load system default trust store (CA certificates)
    if (!SSL_CTX_set_default_verify_paths(ctx_)) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Failed to load default CA paths");
    }

    // 5) Require server certificate verification
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);

    // 6) Optional: Load client certificate for mutual TLS
    // loadClientCertificate("", "");

    // now here we can also set verify depth, callbacks, ciphers list - I'm not too sure about this part, will look into it later
}

SSLContext::~SSLContext()
{
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

SSLContext::SSLContext(SSLContext&& other) noexcept
    : ctx_(other.ctx_)
{
    other.ctx_ = nullptr;
}

SSLContext& SSLContext::operator=(SSLContext&& other) noexcept
{
    if (this != &other) {
        if (ctx_) SSL_CTX_free(ctx_);
        ctx_ = other.ctx_;
        other.ctx_ = nullptr;
    }
    return *this;
}

SSL_CTX* SSLContext::get() const
{
    return ctx_;
}

/*
void SSLContext::loadClientCertificate(const std::string& certFile, 
                                     const std::string& keyFile) {
    if (SSL_CTX_use_certificate_file(ctx_, certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        throw std::runtime_error("Failed to load client certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx_, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        throw std::runtime_error("Failed to load client private key");
    }
}
*/
