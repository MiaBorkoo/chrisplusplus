#pragma once

#include "../models/DataModels.h"
#include "../exceptions/Exceptions.h"
#include "../../../sockets/SSLContext.h"
#include <memory>
#include <string>

/**
 * Specialized client for authentication operations
 * Handles user registration, login, TOTP verification, and session management
 */
class AuthServiceClient {
public:
    AuthServiceClient(SSLContext& ssl_context, 
                     const std::string& host, 
                     const std::string& port);
    ~AuthServiceClient() = default;

    // User registration and authentication
    AuthSessionResponse register_user(const RegisterRequest& request);
    AuthSessionResponse login(const LoginRequest& request);
    MEKResponse verify_totp(const TOTPRequest& request);
    bool logout(const std::string& session_token);
    
    // Password management
    bool change_password(const ChangePasswordRequest& request);
    
    // User information retrieval
    UserSaltsResponse get_user_salts(const std::string& username);

private:
    SSLContext& ssl_context_;
    std::string server_host_;
    std::string server_port_;
}; 