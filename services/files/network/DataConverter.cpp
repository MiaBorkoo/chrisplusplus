#include "DataConverter.h"
#include <nlohmann/json.hpp>
#include <random>
#include <chrono>
#include <algorithm>
#include <cctype>

std::string DataConverter::base64_encode(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return "";
    }
    
    BIO* bio_mem = BIO_new(BIO_s_mem());
    BIO* bio_b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
    bio_b64 = BIO_push(bio_b64, bio_mem);
    
    BIO_write(bio_b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio_b64);
    
    char* encoded_data = nullptr;
    long encoded_len = BIO_get_mem_data(bio_mem, &encoded_data);
    
    std::string result(encoded_data, encoded_len);
    BIO_free_all(bio_b64);
    
    return result;
}

std::vector<uint8_t> DataConverter::base64_decode(const std::string& encoded) {
    if (encoded.empty()) {
        return {};
    }
    
    BIO* bio_mem = BIO_new_mem_buf(encoded.c_str(), static_cast<int>(encoded.length()));
    BIO* bio_b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
    bio_b64 = BIO_push(bio_b64, bio_mem);
    
    std::vector<uint8_t> decoded_data(encoded.length());
    int decoded_len = BIO_read(bio_b64, decoded_data.data(), static_cast<int>(decoded_data.size()));
    BIO_free_all(bio_b64);
    
    if (decoded_len <= 0) {
        throw FileException(FileError::DECRYPTION_FAILED, "Failed to decode base64 data");
    }
    
    decoded_data.resize(decoded_len);
    return decoded_data;
}

std::string DataConverter::create_multipart_boundary() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream boundary;
    boundary << "----ChrisPlusPlus";
    for (int i = 0; i < 16; ++i) {
        boundary << std::hex << dis(gen);
    }
    
    return boundary.str();
}

std::string DataConverter::build_multipart_form_data(
    const std::vector<uint8_t>& file_data,
    const FileUploadRequest& metadata,
    const std::string& boundary) {
    
    std::stringstream form_data;
    
    // Add file data (binary)
    form_data << "--" << boundary << "\r\n";
    form_data << "Content-Disposition: form-data; name=\"file\"; filename=\"encrypted_file\"\r\n";
    form_data << "Content-Type: application/octet-stream\r\n\r\n";
    form_data.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());
    form_data << "\r\n";
    
    // Add file_id (if present)
    if (!metadata.file_id.empty()) {
        form_data << "--" << boundary << "\r\n";
        form_data << "Content-Disposition: form-data; name=\"file_id\"\r\n\r\n";
        form_data << metadata.file_id << "\r\n";
    }
    
    // Add filename_encrypted
    form_data << "--" << boundary << "\r\n";
    form_data << "Content-Disposition: form-data; name=\"filename_encrypted\"\r\n\r\n";
    form_data << metadata.filename_encrypted << "\r\n";
    
    // Add file_size_encrypted
    form_data << "--" << boundary << "\r\n";
    form_data << "Content-Disposition: form-data; name=\"file_size_encrypted\"\r\n\r\n";
    form_data << metadata.file_size_encrypted << "\r\n";
    
    // Add file_data_hmac
    form_data << "--" << boundary << "\r\n";
    form_data << "Content-Disposition: form-data; name=\"file_data_hmac\"\r\n\r\n";
    form_data << metadata.file_data_hmac << "\r\n";
    
    // End boundary
    form_data << "--" << boundary << "--\r\n";
    
    return form_data.str();
}

FileShareRequest DataConverter::to_api_share_request(
    const std::string& file_id,
    const std::string& recipient_username,
    const std::vector<uint8_t>& encrypted_dek,
    const std::string& share_grant_hmac,
    const std::string& share_chain_hmac,
    std::optional<uint64_t> expires_at) {
    
    FileShareRequest request;
    request.file_id = file_id;
    request.recipient_username = recipient_username;
    request.encrypted_data_key = encrypted_dek;  // Will be base64 encoded in JSON
    request.share_grant_hmac = share_grant_hmac;
    request.share_chain_hmac = share_chain_hmac;
    request.expires_at = expires_at;
    
    return request;
}

std::vector<uint8_t> DataConverter::extract_binary_from_api(const std::string& base64_data) {
    return base64_decode(base64_data);
}

std::string DataConverter::build_query_string(const std::map<std::string, std::string>& params) {
    if (params.empty()) {
        return "";
    }
    
    std::stringstream query;
    bool first = true;
    
    for (const auto& [key, value] : params) {
        if (!first) {
            query << "&";
        }
        query << key << "=" << value;  // TODO: URL encode if needed
        first = false;
    }
    
    return query.str();
}

std::string DataConverter::to_json_string(const RegisterRequest& request) {
    nlohmann::json j;
    j["username"] = request.username;
    j["auth_salt"] = request.auth_salt;
    j["enc_salt"] = request.enc_salt;
    j["auth_key"] = request.auth_key;
    j["encrypted_mek"] = request.encrypted_mek;
    j["totp_secret"] = request.totp_secret;
    j["public_key"] = request.public_key;
    j["user_data_hmac"] = request.user_data_hmac;
    
    return j.dump();
}

std::string DataConverter::to_json_string(const LoginRequest& request) {
    nlohmann::json j;
    j["username"] = request.username;
    j["auth_key"] = request.auth_key;
    
    return j.dump();
}

std::string DataConverter::to_json_string(const TOTPRequest& request) {
    nlohmann::json j;
    j["username"] = request.username;
    j["totp_code"] = request.totp_code;
    
    return j.dump();
}

std::string DataConverter::to_json_string(const ChangePasswordRequest& request) {
    nlohmann::json j;
    j["username"] = request.username;
    j["old_auth_key"] = request.old_auth_key;
    j["new_auth_key"] = request.new_auth_key;
    j["new_encrypted_mek"] = request.new_encrypted_mek;
    j["totp_code"] = request.totp_code;
    
    return j.dump();
}

std::string DataConverter::to_json_string(const FileShareRequest& request) {
    nlohmann::json j;
    j["file_id"] = request.file_id;
    j["recipient_username"] = request.recipient_username;
    j["encrypted_data_key"] = base64_encode(request.encrypted_data_key);
    j["share_grant_hmac"] = request.share_grant_hmac;
    j["share_chain_hmac"] = request.share_chain_hmac;
    
    if (request.expires_at.has_value()) {
        j["expires_at"] = request.expires_at.value();
    } else {
        j["expires_at"] = nullptr;
    }
    
    return j.dump();
}

std::string DataConverter::to_json_string(const FileDeleteRequest& request) {
    nlohmann::json j;
    j["file_id"] = request.file_id;
    
    return j.dump();
}

template<>
UserSaltsResponse DataConverter::parse_json_response<UserSaltsResponse>(const std::string& json_body) {
    nlohmann::json j = nlohmann::json::parse(json_body);
    
    UserSaltsResponse response;
    response.auth_salt = j["auth_salt"];
    response.enc_salt = j["enc_salt"];
    
    return response;
}

template<>
FileUploadResponse DataConverter::parse_json_response<FileUploadResponse>(const std::string& json_body) {
    nlohmann::json j = nlohmann::json::parse(json_body);
    
    FileUploadResponse response;
    response.file_id = j["file_id"];
    response.server_storage_path = j["server_storage_path"];
    response.upload_timestamp = j["upload_timestamp"];
    
    return response;
}

template<>
FileDownloadResponse DataConverter::parse_json_response<FileDownloadResponse>(const std::string& json_body) {
    nlohmann::json j = nlohmann::json::parse(json_body);
    
    FileDownloadResponse response;
    response.file_data = base64_decode(j["file_data"]);
    response.filename_encrypted = j["filename_encrypted"];
    response.file_size_encrypted = j["file_size_encrypted"];
    response.file_data_hmac = j["file_data_hmac"];
    
    return response;
}

template<>
FileMetadataResponse DataConverter::parse_json_response<FileMetadataResponse>(const std::string& json_body) {
    nlohmann::json j = nlohmann::json::parse(json_body);
    
    FileMetadataResponse response;
    response.file_id = j["file_id"];
    response.filename_encrypted = j["filename_encrypted"];
    response.file_size_encrypted = j["file_size_encrypted"];
    response.upload_timestamp = j["upload_timestamp"];
    response.file_data_hmac = j["file_data_hmac"];
    response.server_storage_path = j["server_storage_path"];
    
    return response;
}

template<>
FileShareResponse DataConverter::parse_json_response<FileShareResponse>(const std::string& json_body) {
    nlohmann::json j = nlohmann::json::parse(json_body);
    
    FileShareResponse response;
    response.share_id = j["share_id"];
    response.granted_at = j["granted_at"];
    
    return response;
}

template<>
UserFilesResponse DataConverter::parse_json_response<UserFilesResponse>(const std::string& json_body) {
    nlohmann::json j = nlohmann::json::parse(json_body);
    
    UserFilesResponse response;
    
    // Parse owned files
    for (const auto& file_json : j["owned_files"]) {
        FileResponse file;
        file.file_id = file_json["file_id"];
        file.filename_encrypted = file_json["filename_encrypted"];
        file.file_size_encrypted = file_json["file_size_encrypted"];
        file.upload_timestamp = file_json["upload_timestamp"];
        file.file_data_hmac = file_json["file_data_hmac"];
        file.server_storage_path = file_json["server_storage_path"];
        response.owned_files.push_back(file);
    }
    
    // Parse shared files
    for (const auto& file_json : j["shared_files"]) {
        SharedFileResponse file;
        file.file_id = file_json["file_id"];
        file.filename_encrypted = file_json["filename_encrypted"];
        file.file_size_encrypted = file_json["file_size_encrypted"];
        file.upload_timestamp = file_json["upload_timestamp"];
        file.file_data_hmac = file_json["file_data_hmac"];
        file.share_id = file_json["share_id"];
        response.shared_files.push_back(file);
    }
    
    return response;
}

template<>
MEKResponse DataConverter::parse_json_response<MEKResponse>(const std::string& json_body) {
    nlohmann::json j = nlohmann::json::parse(json_body);
    
    MEKResponse response;
    response.success = j["success"];
    response.session_token = j["session_token"];
    response.encrypted_mek = j["encrypted_mek"];
    response.expires_at = j["expires_at"];
    
    return response;
}

template<>
AuthSessionResponse DataConverter::parse_json_response<AuthSessionResponse>(const std::string& json_body) {
    nlohmann::json j = nlohmann::json::parse(json_body);
    
    AuthSessionResponse response;
    
    // Check if the response contains temp_token (JavaScript expects this)
    if (j.contains("temp_token")) {
        response.totp_challenge_token = j["temp_token"];
        response.login_success = true;
    } else if (j.contains("totp_challenge_token")) {
        response.totp_challenge_token = j["totp_challenge_token"];
        response.login_success = true;
    } else if (j.contains("session_token")) {
        response.session_token = j["session_token"];
        response.login_success = true;
    } else {
        // If the response is empty or just indicates success, that's valid for login
        response.login_success = true;
    }
    
    return response;
}

std::string DataConverter::escape_json_string(const std::string& str) {
    std::stringstream escaped;
    for (char c : str) {
        switch (c) {
            case '"': escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if (std::iscntrl(c)) {
                    escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    escaped << c;
                }
                break;
        }
    }
    return escaped.str();
}

std::string DataConverter::hex_encode(const std::vector<uint8_t>& data) {
    std::stringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        hex_stream << std::setw(2) << static_cast<unsigned>(byte);
    }
    return hex_stream.str();
} 