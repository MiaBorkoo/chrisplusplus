#include "AuthServiceClient.h"
#include "DataConverter.h"
#include "../../../httpC/HttpClient.h"
#include "../../../httpC/HttpRequest.h"
#include "../../../httpC/HttpResponse.h"
#include <iostream>
#include <sstream>
#include <stdexcept>

AuthServiceClient::AuthServiceClient(SSLContext& ssl_context, 
                                   const std::string& host, 
                                   const std::string& port)
    : ssl_context_(ssl_context), server_host_(host), server_port_(port) {
}

AuthSessionResponse AuthServiceClient::register_user(const RegisterRequest& request) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "POST";
        http_request.path = "/api/auth/register";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Content-Type"] = "application/json";
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        http_request.body = DataConverter::to_json_string(request);
        
        HttpResponse response = client.sendRequest(http_request);
        
        if (response.statusCode != 200) {
            throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                              "Registration failed with status: " + std::to_string(response.statusCode));
        }
        
        // For register, we don't expect a specific response structure
        // Return empty AuthSessionResponse indicating success
        return {};
        
    } catch (const std::exception& e) {
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("Registration request failed: ") + e.what());
    }
}

AuthSessionResponse AuthServiceClient::login(const LoginRequest& request) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "POST";
        http_request.path = "/api/auth/login";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Content-Type"] = "application/json";
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        http_request.body = DataConverter::to_json_string(request);
        
        std::cout << "Making login request to: " << http_request.path << std::endl;
        std::cout << "Request body: " << http_request.body << std::endl;
        HttpResponse response = client.sendRequest(http_request);
        std::cout << "Login response status: " << response.statusCode << std::endl;
        std::cout << "Login response body: " << response.body << std::endl;
        
        if (response.statusCode != 200) {
            throw FileException(FileError::UNAUTHORIZED_ACCESS, 
                              "Login failed with status: " + std::to_string(response.statusCode));
        }
        
        // Parse the JSON response to get the temp_token or session info
        std::cout << "Login response body: " << response.body << std::endl;
        return DataConverter::parse_json_response<AuthSessionResponse>(response.body);
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        std::cout << "Exception in login: " << e.what() << std::endl;
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("Login request failed: ") + e.what());
    }
}

MEKResponse AuthServiceClient::verify_totp(const TOTPRequest& request) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "POST";
        http_request.path = "/api/auth/totp";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Content-Type"] = "application/json";
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        http_request.body = DataConverter::to_json_string(request);
        
        HttpResponse response = client.sendRequest(http_request);
        
        if (response.statusCode != 200) {
            throw FileException(FileError::UNAUTHORIZED_ACCESS, 
                              "TOTP verification failed with status: " + std::to_string(response.statusCode));
        }
        
        return DataConverter::parse_json_response<MEKResponse>(response.body);
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("TOTP verification failed: ") + e.what());
    }
}

bool AuthServiceClient::logout(const std::string& session_token) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "POST";
        http_request.path = "/api/auth/logout";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Authorization"] = "Bearer " + session_token;
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        
        HttpResponse response = client.sendRequest(http_request);
        
        return response.statusCode == 200;
        
    } catch (const std::exception& e) {
        return false;
    }
}

bool AuthServiceClient::change_password(const ChangePasswordRequest& request) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "POST";
        http_request.path = "/api/auth/change_password";
        http_request.headers["Host"] = server_host_;
        http_request.headers["Content-Type"] = "application/json";
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        http_request.body = DataConverter::to_json_string(request);
        
        HttpResponse response = client.sendRequest(http_request);
        
        return response.statusCode == 200;
        
    } catch (const std::exception& e) {
        return false;
    }
}

UserSaltsResponse AuthServiceClient::get_user_salts(const std::string& username) {
    try {
        HttpClient client(ssl_context_, server_host_, server_port_);
        
        HttpRequest http_request;
        http_request.method = "GET";
        http_request.path = "/api/user/" + username + "/salts";
        http_request.headers["Host"] = server_host_;
        http_request.headers["User-Agent"] = "ChrisPlusPlus-Files/1.0";
        
        std::cout << "Making request to: " << http_request.path << std::endl;
        HttpResponse response = client.sendRequest(http_request);
        std::cout << "Response status: " << response.statusCode << std::endl;
        std::cout << "Response body: " << response.body << std::endl;
        
        if (response.statusCode != 200) {
            throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                              "Failed to get user salts with status: " + std::to_string(response.statusCode));
        }
        
        return DataConverter::parse_json_response<UserSaltsResponse>(response.body);
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        std::cout << "Exception in get_user_salts: " << e.what() << std::endl;
        throw FileException(FileError::SERVER_COMMUNICATION_ERROR, 
                          std::string("Get user salts failed: ") + e.what());
    }
} 