#include <iostream>
#include "../sockets/SSLContext.h"
#include "../httpC/HttpClient.h"

int main() {
    try {
        // 1) Initialize OpenSSL
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
        std::cout << "\n=== HTTP Response ===\n";
        std::cout << "Status: " << resp.statusCode << " " << resp.statusMessage << std::endl;
        std::cout << "\nHeaders:\n";
        for (const auto& [key, value] : resp.headers) {
            std::cout << key << ": " << value << std::endl;
        }
        std::cout << "\nBody:\n" << resp.body << std::endl;
        
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "HTTP test failed: " << ex.what() << std::endl;
        return 1;
    }
} 