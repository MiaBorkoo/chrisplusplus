#include "FileEncryptionEngine.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <type_traits>

FileEncryptionEngine::FileEncryptionEngine() 
    : compression_engine_(std::make_unique<CompressionEngine>()),
      serialization_engine_(std::make_unique<SerializationEngine>()) {
    // Initialize OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Verify OpenSSL is properly linked and available
    if (RAND_status() != 1) {
        throw FileException(FileError::ENCRYPTION_FAILED, "OpenSSL PRNG not properly seeded");
    }
}

FileEncryptionContext FileEncryptionEngine::encrypt_file(
    const std::vector<uint8_t>& file_data,
    const std::vector<uint8_t>& mek) {
    
    if (mek.empty()) {
        throw FileException(FileError::INVALID_DEK, "MEK cannot be empty");
    }
    
    FileEncryptionContext context;
    std::vector<uint8_t> encrypted_data;
    
    try {
        // Generate unique 256-bit DEK using OpenSSL RAND_bytes
        context.dek = generate_random_bytes(32); // 256 bits = 32 bytes
        
        // Generate unique 96-bit IV for AES-256-GCM
        context.iv = generate_random_bytes(12); // 96 bits = 12 bytes for GCM
        
        // Generate UUID for file_id using random bytes
        std::vector<uint8_t> uuid_bytes = generate_random_bytes(16);
        std::stringstream uuid_stream;
        uuid_stream << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16; ++i) {
            if (i == 4 || i == 6 || i == 8 || i == 10) {
                uuid_stream << "-";
            }
            uuid_stream << std::setw(2) << static_cast<unsigned>(uuid_bytes[i]);
        }
        context.file_id = uuid_stream.str();
        
        // Store original size
        context.original_size = file_data.size();
        
        // Encrypt file_data using AES-256-GCM with DEK and IV
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to create EVP context");
        }
        
        // Initialize encryption with AES-256-GCM
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to initialize AES-256-GCM");
        }
        
        // Set IV length (96 bits for GCM)
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to set IV length");
        }
        
        // Initialize key and IV
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, context.dek.data(), context.iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to set key and IV");
        }
        
        // Encrypt the data
        encrypted_data.resize(file_data.size());
        int len = 0;
        int encrypted_len = 0;
        
        if (EVP_EncryptUpdate(ctx, encrypted_data.data(), &len, file_data.data(), static_cast<int>(file_data.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to encrypt data");
        }
        encrypted_len = len;
        
        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, encrypted_data.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to finalize encryption");
        }
        encrypted_len += len;
        
        // Resize to actual encrypted length
        encrypted_data.resize(encrypted_len);
        
        // Get the authentication tag (128 bits = 16 bytes for GCM)
        context.auth_tag.resize(16);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, context.auth_tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to get authentication tag");
        }
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Calculate HMAC of encrypted file using MEK
        context.hmac = calculate_file_hmac(encrypted_data, mek);
        
        // Note: DEK is kept in context for later decryption
        // Caller is responsible for secure cleanup
        
        return context;
        
    } catch (const FileException&) {
        // Secure zero DEK on exception
        secure_zero_memory(context.dek);
        throw;
    } catch (const std::exception& e) {
        // Secure zero DEK on exception
        secure_zero_memory(context.dek);
        throw FileException(FileError::ENCRYPTION_FAILED, std::string("Encryption failed: ") + e.what());
    }
}

std::vector<uint8_t> FileEncryptionEngine::decrypt_file(
    const std::vector<uint8_t>& encrypted_data,
    const FileEncryptionContext& context) {
    
    if (context.dek.empty() || context.iv.empty() || context.auth_tag.empty()) {
        throw FileException(FileError::INVALID_DEK, "Invalid encryption context");
    }
    
    try {
        // Create a copy of DEK for secure cleanup
        std::vector<uint8_t> dek_copy = context.dek;
        
        // Decrypt encrypted_data using AES-256-GCM with context.dek and context.iv
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            secure_zero_memory(dek_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to create EVP context");
        }
        
        // Initialize decryption with AES-256-GCM
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            secure_zero_memory(dek_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to initialize AES-256-GCM");
        }
        
        // Set IV length (96 bits for GCM)
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            secure_zero_memory(dek_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to set IV length");
        }
        
        // Initialize key and IV
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, dek_copy.data(), context.iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            secure_zero_memory(dek_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to set key and IV");
        }
        
        // Decrypt the data
        std::vector<uint8_t> decrypted_data(encrypted_data.size());
        int len = 0;
        int decrypted_len = 0;
        
        if (EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, encrypted_data.data(), static_cast<int>(encrypted_data.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            secure_zero_memory(dek_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to decrypt data");
        }
        decrypted_len = len;
        
        // Set the authentication tag for verification
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(context.auth_tag.size()), 
                               const_cast<uint8_t*>(context.auth_tag.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            secure_zero_memory(dek_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to set authentication tag");
        }
        
        // Finalize decryption and verify authentication tag
        if (EVP_DecryptFinal_ex(ctx, decrypted_data.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            secure_zero_memory(dek_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Authentication verification failed");
        }
        decrypted_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Resize to actual decrypted length
        decrypted_data.resize(decrypted_len);
        
        // Secure zero DEK from memory after use
        secure_zero_memory(dek_copy);
        
        return decrypted_data;
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::DECRYPTION_FAILED, std::string("Decryption failed: ") + e.what());
    }
}

std::string FileEncryptionEngine::calculate_file_hmac(
    const std::vector<uint8_t>& file_data,
    const std::vector<uint8_t>& mek) {
    if (mek.empty()) {
        throw FileException(FileError::INVALID_DEK, "MEK cannot be empty for HMAC calculation");
    }
    
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    
    // Calculate HMAC-SHA256 of file_data using MEK as key
    unsigned char* result = HMAC(EVP_sha256(), 
                                mek.data(), static_cast<int>(mek.size()),
                                file_data.data(), file_data.size(),
                                hmac_result, &hmac_len);
    
    if (!result) {
        throw FileException(FileError::ENCRYPTION_FAILED, "Failed to calculate HMAC");
    }
    
    // Convert HMAC to hex string
    std::stringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hmac_len; ++i) {
        hex_stream << std::setw(2) << static_cast<unsigned>(hmac_result[i]);
    }
    
    return hex_stream.str();
}

bool FileEncryptionEngine::verify_file_integrity(
    const std::vector<uint8_t>& file_data,
    const std::string& expected_hmac,
    const std::vector<uint8_t>& mek) {
    // TODO: Calculate HMAC of file_data using MEK with OpenSSL HMAC functions
    // TODO: Compare calculated HMAC with expected_hmac using constant-time comparison (CRYPTO_memcmp)
    // TODO: Return true if HMACs match, false otherwise
    return false;
}

std::vector<uint8_t> FileEncryptionEngine::generate_dek() {
    // TODO: Generate 256-bit (32 bytes) random key using OpenSSL RAND_bytes
    // TODO: Return as vector<uint8_t>
    return {};
}

std::vector<uint8_t> FileEncryptionEngine::encrypt_dek_for_recipient(
    const std::vector<uint8_t>& dek,
    const nlohmann::json& recipient_public_key) {
    // TODO: Parse RSA public key from JSON format using OpenSSL PEM functions
    // TODO: Encrypt DEK using RSA-OAEP with recipient's public key using OpenSSL EVP_PKEY functions
    // TODO: Return encrypted DEK as vector<uint8_t>
    // TODO: Throw ENCRYPTION_FAILED exception on failure
    return {};
}

std::vector<uint8_t> FileEncryptionEngine::decrypt_dek_from_share(
    const std::vector<uint8_t>& encrypted_dek,
    const std::vector<uint8_t>& private_key) {
    // TODO: Decrypt encrypted_dek using RSA-OAEP with user's private key using OpenSSL EVP_PKEY functions
    // TODO: Return decrypted DEK as vector<uint8_t>
    // TODO: Throw DECRYPTION_FAILED exception on failure
    // TODO: Secure zero private key from memory after use with OPENSSL_cleanse
    return {};
}

std::string FileEncryptionEngine::encrypt_metadata(
    const std::string& data,
    const std::vector<uint8_t>& mek) {
    // TODO: Encrypt data using AES-256-GCM with MEK using OpenSSL EVP functions
    // TODO: Generate random IV for each encryption using OpenSSL RAND_bytes
    // TODO: Prepend IV to encrypted data
    // TODO: Return as base64 encoded string using OpenSSL BIO_f_base64
    return "";
}

std::string FileEncryptionEngine::decrypt_metadata(
    const std::string& encrypted_data,
    const std::vector<uint8_t>& mek) {
    // TODO: Decode base64 encrypted_data using OpenSSL BIO_f_base64
    // TODO: Extract IV from beginning of data
    // TODO: Decrypt remaining data using AES-256-GCM with MEK and IV using OpenSSL EVP functions
    // TODO: Return decrypted string
    // TODO: Throw DECRYPTION_FAILED exception on failure
    return "";
}

std::string FileEncryptionEngine::generate_share_grant_hmac(
    const FileShareRequest& request,
    const std::vector<uint8_t>& mek) {
    // TODO: Create canonical string from FileShareRequest fields
    // TODO: Include file_id, recipient_username, encrypted_data_key, expires_at
    // TODO: Calculate HMAC-SHA256 using MEK as key with OpenSSL HMAC functions
    // TODO: Return as hex string (64 characters)
    return "";
}

std::string FileEncryptionEngine::generate_share_chain_hmac(
    const std::string& file_id,
    const std::string& recipient_username,
    const std::vector<uint8_t>& mek) {
    // TODO: Create canonical string from file_id and recipient_username
    // TODO: Calculate HMAC-SHA256 using MEK as key with OpenSSL HMAC functions
    // TODO: Return as hex string (64 characters)
    return "";
}

std::vector<uint8_t> FileEncryptionEngine::generate_random_bytes(size_t length) {
    std::vector<uint8_t> random_bytes(length);
    if (RAND_bytes(random_bytes.data(), static_cast<int>(length)) != 1) {
        throw FileException(FileError::ENCRYPTION_FAILED, "Failed to generate random bytes");
    }
    return random_bytes;
}

template<typename ContentType>
FileEncryptionContext FileEncryptionEngine::encrypt_content(
    const ContentType& content_data,
    const std::vector<uint8_t>& mek,
    ContentTypeEnum content_type) {
    
    try {
        // TODO: Serialize content_data using serialization_engine_
        std::vector<uint8_t> serialized_data;
        if constexpr (std::is_same_v<ContentType, FileContent>) {
            serialized_data = serialization_engine_->serialize_file_content(content_data);
        } else if constexpr (std::is_same_v<ContentType, FolderContent>) {
            serialized_data = serialization_engine_->serialize_folder_content(content_data);
        } else {
            throw FileException(FileError::INVALID_CONTENT_TYPE, "Unsupported content type");
        }
        
        // TODO: Compress serialized data using compression_engine_
        std::vector<uint8_t> compressed_data = compression_engine_->compress_data(serialized_data);
        
        // TODO: Encrypt compressed data using existing encrypt_file method
        FileEncryptionContext context = encrypt_file(compressed_data, mek);
        
        // TODO: Update context with content type and compression info
        context.content_type = content_type;
        context.is_compressed = true;
        context.compressed_size = compressed_data.size();
        
        return context;
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::ENCRYPTION_FAILED, 
                          std::string("Content encryption failed: ") + e.what());
    }
}

template<typename ContentType>
ContentType FileEncryptionEngine::decrypt_content(
    const std::vector<uint8_t>& encrypted_data,
    const FileEncryptionContext& context) {
    
    try {
        // TODO: Decrypt encrypted_data using existing decrypt_file method
        std::vector<uint8_t> compressed_data = decrypt_file(encrypted_data, context);
        
        // TODO: Decompress data using compression_engine_ if needed
        std::vector<uint8_t> serialized_data;
        if (context.is_compressed) {
            serialized_data = compression_engine_->decompress_data(compressed_data);
        } else {
            serialized_data = compressed_data;
        }
        
        // TODO: Deserialize based on context.content_type using serialization_engine_
        if constexpr (std::is_same_v<ContentType, FileContent>) {
            if (context.content_type != ContentTypeEnum::FILE) {
                throw FileException(FileError::INVALID_CONTENT_TYPE, "Content type mismatch: expected FILE");
            }
            return serialization_engine_->deserialize_file_content(serialized_data);
        } else if constexpr (std::is_same_v<ContentType, FolderContent>) {
            if (context.content_type != ContentTypeEnum::FOLDER) {
                throw FileException(FileError::INVALID_CONTENT_TYPE, "Content type mismatch: expected FOLDER");
            }
            return serialization_engine_->deserialize_folder_content(serialized_data);
        } else {
            throw FileException(FileError::INVALID_CONTENT_TYPE, "Unsupported content type for deserialization");
        }
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::DECRYPTION_FAILED, 
                          std::string("Content decryption failed: ") + e.what());
    }
}

// Explicit template instantiations for supported content types
template FileEncryptionContext FileEncryptionEngine::encrypt_content<FileContent>(
    const FileContent& content_data,
    const std::vector<uint8_t>& mek,
    ContentTypeEnum content_type);

template FileEncryptionContext FileEncryptionEngine::encrypt_content<FolderContent>(
    const FolderContent& content_data,
    const std::vector<uint8_t>& mek,
    ContentTypeEnum content_type);

template FileContent FileEncryptionEngine::decrypt_content<FileContent>(
    const std::vector<uint8_t>& encrypted_data,
    const FileEncryptionContext& context);

template FolderContent FileEncryptionEngine::decrypt_content<FolderContent>(
    const std::vector<uint8_t>& encrypted_data,
    const FileEncryptionContext& context);

void FileEncryptionEngine::secure_zero_memory(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
} 