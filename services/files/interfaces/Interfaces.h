#pragma once

#include "../models/DataModels.h"
#include <memory>

// Interface for TOFU system integration (Person 1)
// Used by file service for verifying recipient identity during file sharing
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