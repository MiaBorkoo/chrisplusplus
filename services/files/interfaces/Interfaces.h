#pragma once

#include "../models/DataModels.h"
#include <memory>

// Placeholder interface for TOFU system (Person 1)
class TOFUInterface {
public:
    virtual ~TOFUInterface() = default;
    
    virtual IdentityVerificationResponse verify_recipient_identity(
        const IdentityVerificationRequest& request) = 0;
    
    virtual bool is_certificate_trusted(
        const std::string& username,
        const std::vector<uint8_t>& certificate_hash) = 0;
    
    virtual void notify_sharing_event(
        const std::string& recipient_username,
        const std::string& file_id) = 0;
};

// Placeholder interface for Authentication system (Person 3)  
class AuthenticationInterface {
public:
    virtual ~AuthenticationInterface() = default;
    
    virtual AuthSessionResponse authenticate_user(const AuthSessionRequest& request) = 0;
    
    virtual MEKResponse verify_totp_and_get_mek(const MEKRequest& request) = 0;
    
    virtual UserKeyInfo get_user_public_key(const std::string& username) = 0;
    
    virtual bool validate_session(const std::string& session_token) = 0;
    
    virtual std::string get_current_username(const std::string& session_token) = 0;
    
    virtual UserSaltsResponse get_user_salts(const std::string& username) = 0;
}; 