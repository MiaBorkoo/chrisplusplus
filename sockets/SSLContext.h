// SSLContext wrapper for OpenSSL
#pragma once

#include <openssl/ssl.h>
#include <string>

//simple header file for the ssl context class
class SSLContext {
    public:
        static void initializeOpenSSL();

        //constructor and destructor
        SSLContext();
        ~SSLContext();


        SSLContext(const SSLContext&) = delete;
        SSLContext& operator=(const SSLContext&) = delete;

        
        SSLContext(SSLContext&& other) noexcept;
        SSLContext& operator=(SSLContext&& other) noexcept;

        //get the raw SSL_CTX pointer for use in SSLConnection - chris would be proud he asked me about get()
        SSL_CTX* get() const;

        void loadClientCertificate(const std::string& certFile, 
                                 const std::string& keyFile);

    private:
        SSL_CTX* ctx_;
};
