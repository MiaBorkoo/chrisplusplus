// test_ssl.cpp
#include <iostream>
#include "SSLContext.h"
#include "SSLConnection.h"

//this is the main file for testing the ssl library with a simple http request that cursor made for me :)
int main()
{
    try {
        // 1) Init the OpenSSL library
        SSLContext::initializeOpenSSL();

        // 2) Build a context with secure defaults
        SSLContext ctx;

        // 3) Connect to example.com on port 443
        SSLConnection conn(ctx, "example.com", "443");

        // 4) Send a minimal HTTP GET
        const std::string req =
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Connection: close\r\n\r\n";
        conn.send(req.data(), req.size());

        // 5) Read & print response
        char buf[4096];
        ssize_t n;
        while ((n = conn.receive(buf, sizeof(buf)-1)) > 0) {
            buf[n] = '\0';
            std::cout << buf;
        }
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "Test failed: " << ex.what() << "\n";
        return 1;
    }
}
