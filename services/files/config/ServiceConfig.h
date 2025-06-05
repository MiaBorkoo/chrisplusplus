#pragma once

#include <string>

namespace ServiceConfig {
    // Server configuration constants
    namespace Server {
        // Default development server settings
        constexpr const char* DEFAULT_HOST = "chrisplusplus.gobbler.info";
        constexpr const char* DEFAULT_PORT = "443";
        constexpr const char* DEFAULT_URL = "https://chrisplusplus.gobbler.info";
        
        // Default SSL ports
        constexpr const char* DEFAULT_HTTPS_PORT = "443";
        constexpr const char* DEFAULT_HTTP_PORT = "80";
        
        // Production server settings (to be overridden by environment/config)
        constexpr const char* PRODUCTION_HOST = "chrisplusplus.gobbler.info";
        constexpr const char* PRODUCTION_PORT = "443";
        constexpr const char* PRODUCTION_URL = "https://chrisplusplus.gobbler.info";
    }
    
    // Client configuration
    namespace Client {
        constexpr const char* USER_AGENT = "ChrisPlusPlus-Files/1.0";
        constexpr int DEFAULT_TIMEOUT_SECONDS = 30;
        constexpr int UPLOAD_TIMEOUT_SECONDS = 60;
        constexpr int DOWNLOAD_TIMEOUT_SECONDS = 60;
    }
    
    // API endpoints
    namespace Endpoints {
        // Authentication endpoints
        constexpr const char* AUTH_REGISTER = "/api/auth/register";
        constexpr const char* AUTH_LOGIN = "/api/auth/login";
        constexpr const char* AUTH_REFRESH = "/api/auth/refresh";
        constexpr const char* AUTH_LOGOUT = "/api/auth/logout";
        constexpr const char* AUTH_CHANGE_PASSWORD = "/api/auth/change_password";
        
        // User endpoints
        constexpr const char* USER_SALTS = "/api/user/{username}/salts";
        
        // Files endpoints
        constexpr const char* FILES_BASE = "/api/files";
        constexpr const char* FILES_UPLOAD = "/api/files/upload";
        constexpr const char* FILES_DOWNLOAD = "/api/files/{file_id}/download";
        constexpr const char* FILES_METADATA = "/api/files/{file_id}/metadata";
        constexpr const char* FILES_LIST = "/api/files/";
        constexpr const char* FILES_DELETE = "/api/files/delete";
        constexpr const char* FILES_SHARE = "/api/files/share";
        constexpr const char* FILES_REVOKE_SHARE = "/api/files/share/{share_id}";
        constexpr const char* FILES_SHARES_LIST = "/api/files/{file_id}/shares";
        constexpr const char* FILES_SHARES_RECEIVED = "/api/files/shares/received";
        constexpr const char* FILES_AUDIT = "/api/files/{file_id}/audit";
        
        // Root endpoint
        constexpr const char* ROOT = "/";
    }
} 