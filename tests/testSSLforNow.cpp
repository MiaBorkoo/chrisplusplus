// test_ssl.cpp
#include <iostream>
#include "../sockets/SSLContext.h"
#include "../sockets/SSLConnection.h"
#include "../httpC/HttpClient.h"

void testRawSSL() {
    std::cout << "=== Testing Raw SSL Connection ===\n";
    
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
    std::cout << "Raw SSL Response:\n";
    while ((n = conn.receive(buf, sizeof(buf)-1)) > 0) {
        buf[n] = '\0';
        std::cout << buf;
    }
    std::cout << "\n\n";
}

void testHTTPClient() {
    std::cout << "=== Testing HTTP Client ===\n";
    
    // 1) Initialize OpenSSL (already done, but safe to call again)
    SSLContext::initializeOpenSSL();
    
    // 2) Create SSL context
    SSLContext ctx;
    
    // 3) Create HTTP client
    HttpClient client(ctx, "httpbin.org", "443");
    
    // 4) Create HTTP request
    HttpRequest req;
    req.method = "GET";
    req.path = "/get";
    req.headers["Host"] = "httpbin.org";
    req.headers["User-Agent"] = "ChrisPlusPlus/1.0";
    req.headers["Connection"] = "close";
    
    std::cout << "Sending HTTP request:\n";
    std::cout << req.serialize() << std::endl;
    
    // 5) Send request and get response
    HttpResponse resp = client.sendRequest(req);
    
    // 6) Display response
    std::cout << "=== HTTP Response ===\n";
    std::cout << "Status: " << resp.statusCode << " " << resp.statusMessage << std::endl;
    std::cout << "\nHeaders:\n";
    for (const auto& [key, value] : resp.headers) {
        std::cout << key << ": " << value << std::endl;
    }
    std::cout << "\nBody:\n" << resp.body << std::endl;
}

//this is the main file for testing the ssl library with a simple http request that cursor made for me :)
int main()
{
    try {
        std::cout << "Starting tests...\n";
        
        // Test 1: Raw SSL connection (your original test)
        testRawSSL();
        std::cout << "Raw SSL test completed!\n";
        
        // Test 2: HTTP client abstraction
        testHTTPClient();
        std::cout << "HTTP test completed!\n";
        
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "Test failed: " << ex.what() << "\n";
        return 1;
    }
}
