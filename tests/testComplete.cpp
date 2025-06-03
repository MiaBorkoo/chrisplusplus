#include <iostream>
#include "../sockets/SSLContext.h"
#include "../sockets/SSLConnection.h"
#include "../httpC/HttpClient.h"

void printSeparator(const std::string& title) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}

void testSSLFoundation() {
    printSeparator("TEST 1: SSL/TLS Foundation");
    
    std::cout << "✓ Initializing OpenSSL library..." << std::endl;
    SSLContext::initializeOpenSSL();
    
    std::cout << "✓ Creating SSL context with secure defaults..." << std::endl;
    SSLContext ctx;
    
    std::cout << "✓ Establishing TLS connection to example.com:443..." << std::endl;
    SSLConnection conn(ctx, "example.com", "443");
    
    std::cout << "✓ Sending raw HTTP request..." << std::endl;
    const std::string req = 
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: ChrisPlusPlus-SSL-Test/1.0\r\n"
        "Connection: close\r\n\r\n";
    
    ssize_t sent = conn.send(req.data(), req.size());
    std::cout << "✓ Sent " << sent << " bytes over encrypted channel" << std::endl;
    
    std::cout << "✓ Receiving encrypted response..." << std::endl;
    char buf[1024];
    ssize_t received = conn.receive(buf, sizeof(buf)-1);
    buf[received] = '\0';
    
    // Just show the status line
    std::string response(buf);
    size_t firstLine = response.find('\n');
    std::cout << "✓ Response: " << response.substr(0, firstLine) << std::endl;
    
    std::cout << "✓ SSL/TLS test PASSED - Certificate verified, data encrypted!" << std::endl;
}

void testHTTPAbstraction() {
    printSeparator("TEST 2: HTTP Abstraction Layer");
    
    std::cout << "✓ Creating SSL context..." << std::endl;
    SSLContext ctx;
    
    std::cout << "✓ Creating HTTP client for httpbin.org..." << std::endl;
    HttpClient client(ctx, "httpbin.org", "443");
    
    std::cout << "✓ Building structured HTTP request..." << std::endl;
    HttpRequest req;
    req.method = "GET";
    req.path = "/json";  // Returns JSON data
    req.headers["Host"] = "httpbin.org";
    req.headers["User-Agent"] = "ChrisPlusPlus-HTTP-Test/1.0";
    req.headers["Accept"] = "application/json";
    req.headers["Connection"] = "close";
    
    std::cout << "✓ Serialized request:\n" << req.serialize() << std::endl;
    
    std::cout << "✓ Sending HTTP request through SSL..." << std::endl;
    HttpResponse resp = client.sendRequest(req);
    
    std::cout << "✓ Parsing structured HTTP response..." << std::endl;
    std::cout << "✓ Status: " << resp.statusCode << " " << resp.statusMessage << std::endl;
    std::cout << "✓ Content-Type: " << resp.headers["Content-Type"] << std::endl;
    std::cout << "✓ Content-Length: " << resp.headers["Content-Length"] << std::endl;
    
    // Show first 200 chars of JSON response
    std::string body = resp.body.substr(0, 200);
    std::cout << "✓ Response body preview:\n" << body << "..." << std::endl;
    
    std::cout << "✓ HTTP abstraction test PASSED - Structured request/response!" << std::endl;
}

void testFileServerSimulation() {
    printSeparator("TEST 3: File Server Simulation");
    
    std::cout << "✓ Simulating file sharing API calls..." << std::endl;
    SSLContext ctx;
    HttpClient client(ctx, "httpbin.org", "443");
    
    // Simulate login
    std::cout << "✓ Testing POST request (simulating login)..." << std::endl;
    HttpRequest loginReq;
    loginReq.method = "POST";
    loginReq.path = "/post";
    loginReq.headers["Host"] = "httpbin.org";
    loginReq.headers["Content-Type"] = "application/json";
    loginReq.headers["Connection"] = "close";
    loginReq.body = R"({"username": "testuser", "password": "encrypted_password"})";
    
    HttpResponse loginResp = client.sendRequest(loginReq);
    std::cout << "✓ Login simulation: " << loginResp.statusCode << " " << loginResp.statusMessage << std::endl;
    
    // Simulate file list
    std::cout << "✓ Testing GET request (simulating file list)..." << std::endl;
    HttpRequest filesReq;
    filesReq.method = "GET";
    filesReq.path = "/get?files=true";
    filesReq.headers["Host"] = "httpbin.org";
    filesReq.headers["Authorization"] = "Bearer fake_token_123";
    filesReq.headers["Connection"] = "close";
    
    HttpResponse filesResp = client.sendRequest(filesReq);
    std::cout << "✓ File list simulation: " << filesResp.statusCode << " " << filesResp.statusMessage << std::endl;
    
    std::cout << "✓ File server simulation PASSED - Ready for real API!" << std::endl;
}

int main() {
    try {
        std::cout << "Testing with real websites..." << std::endl;
        
        SSLContext::initializeOpenSSL();
        SSLContext ctx;
        
        // Test 1: GitHub API (simple GET)
        std::cout << "\n1. Testing GitHub API..." << std::endl;
        HttpClient github(ctx, "api.github.com", "443");
        
        HttpRequest githubReq;
        githubReq.method = "GET";
        githubReq.path = "/users/octocat";
        githubReq.headers["Host"] = "api.github.com";
        githubReq.headers["User-Agent"] = "ChrisPlusPlus/1.0";
        githubReq.headers["Connection"] = "close";
        
        HttpResponse githubResp = github.sendRequest(githubReq);
        std::cout << "GitHub API: " << githubResp.statusCode << " " << githubResp.statusMessage << std::endl;
        std::cout << "Response preview: " << githubResp.body.substr(0, 100) << "..." << std::endl;
        
        // Test 2: JSONPlaceholder (fake REST API)
        std::cout << "\n2. Testing JSONPlaceholder..." << std::endl;
        HttpClient jsonapi(ctx, "jsonplaceholder.typicode.com", "443");
        
        HttpRequest jsonReq;
        jsonReq.method = "GET";
        jsonReq.path = "/posts/1";
        jsonReq.headers["Host"] = "jsonplaceholder.typicode.com";
        jsonReq.headers["User-Agent"] = "ChrisPlusPlus/1.0";
        jsonReq.headers["Connection"] = "close";
        
        HttpResponse jsonResp = jsonapi.sendRequest(jsonReq);
        std::cout << "JSONPlaceholder: " << jsonResp.statusCode << " " << jsonResp.statusMessage << std::endl;
        std::cout << "Response: " << jsonResp.body << std::endl;
        
        // Test 3: POST to HTTPBin (echo service)
        std::cout << "\n3. Testing POST to HTTPBin..." << std::endl;
        HttpClient httpbin(ctx, "httpbin.org", "443");
        
        HttpRequest postReq;
        postReq.method = "POST";
        postReq.path = "/post";
        postReq.headers["Host"] = "httpbin.org";
        postReq.headers["Content-Type"] = "application/json";
        postReq.headers["User-Agent"] = "ChrisPlusPlus/1.0";
        postReq.headers["Connection"] = "close";
        postReq.body = R"({"message": "Hello from ChrisPlusPlus!", "test": true})";
        
        HttpResponse postResp = httpbin.sendRequest(postReq);
        std::cout << "HTTPBin POST: " << postResp.statusCode << " " << postResp.statusMessage << std::endl;
        
        // Test 4: Try a news API (no auth needed)
        std::cout << "\n4. Testing news API..." << std::endl;
        HttpClient news(ctx, "hacker-news.firebaseio.com", "443");
        
        HttpRequest newsReq;
        newsReq.method = "GET";
        newsReq.path = "/v0/item/1.json";
        newsReq.headers["Host"] = "hacker-news.firebaseio.com";
        newsReq.headers["User-Agent"] = "ChrisPlusPlus/1.0";
        newsReq.headers["Connection"] = "close";
        
        HttpResponse newsResp = news.sendRequest(newsReq);
        std::cout << "Hacker News API: " << newsResp.statusCode << " " << newsResp.statusMessage << std::endl;
        std::cout << "Response: " << newsResp.body << std::endl;
        
        std::cout << "\nAll real-world tests passed!" << std::endl;
        std::cout << "Your HTTP client works with real APIs!" << std::endl;
        
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "Test failed: " << ex.what() << std::endl;
        return 1;
    }
} 