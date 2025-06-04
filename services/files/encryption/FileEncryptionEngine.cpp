#include "FileEncryptionEngine.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <type_traits>

FileEncryptionEngine::FileEncryptionEngine() 
    : compression_engine_(std::make_unique<CompressionEngine>()) {
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
    
    if (mek.empty()) {
        throw FileException(FileError::INVALID_DEK, "MEK cannot be empty for HMAC verification");
    }
    
    try {
        // Calculate HMAC of file_data using MEK
        std::string calculated_hmac = calculate_file_hmac(file_data, mek);
        
        // Compare HMACs using constant-time comparison
        if (calculated_hmac.length() != expected_hmac.length()) {
            return false;
        }
        
        // Use OpenSSL constant-time comparison
        return CRYPTO_memcmp(calculated_hmac.c_str(), expected_hmac.c_str(), calculated_hmac.length()) == 0;
        
    } catch (const std::exception&) {
        return false;  // Any error in calculation means verification failed
    }
}

std::vector<uint8_t> FileEncryptionEngine::generate_dek() {
    // Generate 256-bit (32 bytes) random key using OpenSSL RAND_bytes
    return generate_random_bytes(32);
}

std::vector<uint8_t> FileEncryptionEngine::encrypt_dek_for_recipient(
    const std::vector<uint8_t>& dek,
    const nlohmann::json& recipient_public_key) {
    
    if (dek.empty()) {
        throw FileException(FileError::INVALID_DEK, "DEK cannot be empty");
    }
    
    try {
        // Parse RSA public key from JSON format
        if (!recipient_public_key.contains("public_key") || !recipient_public_key["public_key"].is_string()) {
            throw FileException(FileError::ENCRYPTION_FAILED, "Invalid public key format in JSON");
        }
        
        std::string pem_key = recipient_public_key["public_key"].get<std::string>();
        
        // Create BIO from PEM string
        BIO* bio = BIO_new_mem_buf(pem_key.c_str(), static_cast<int>(pem_key.length()));
        if (!bio) {
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to create BIO for public key");
        }
        
        // Parse PEM public key
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        
        if (!pkey) {
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to parse RSA public key from PEM");
        }
        
        // Create encryption context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) {
            EVP_PKEY_free(pkey);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to create EVP_PKEY context");
        }
        
        // Initialize encryption
        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to initialize RSA encryption");
        }
        
        // Set padding to OAEP
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to set RSA OAEP padding");
        }
        
        // Determine buffer size
        size_t encrypted_len = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &encrypted_len, dek.data(), dek.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to determine encrypted DEK size");
        }
        
        // Encrypt DEK
        std::vector<uint8_t> encrypted_dek(encrypted_len);
        if (EVP_PKEY_encrypt(ctx, encrypted_dek.data(), &encrypted_len, dek.data(), dek.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to encrypt DEK with RSA-OAEP");
        }
        
        encrypted_dek.resize(encrypted_len);
        
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        
        return encrypted_dek;
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::ENCRYPTION_FAILED, 
                          std::string("RSA DEK encryption failed: ") + e.what());
    }
}

std::vector<uint8_t> FileEncryptionEngine::decrypt_dek_from_share(
    const std::vector<uint8_t>& encrypted_dek,
    const std::vector<uint8_t>& private_key) {
    
    if (encrypted_dek.empty() || private_key.empty()) {
        throw FileException(FileError::INVALID_DEK, "Encrypted DEK and private key cannot be empty");
    }
    
    // Create a copy of private key for secure cleanup
    std::vector<uint8_t> private_key_copy = private_key;
    
    try {
        // Create BIO from private key bytes
        BIO* bio = BIO_new_mem_buf(private_key_copy.data(), static_cast<int>(private_key_copy.size()));
        if (!bio) {
            secure_zero_memory(private_key_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to create BIO for private key");
        }
        
        // Parse PEM private key
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        
        if (!pkey) {
            secure_zero_memory(private_key_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to parse RSA private key from PEM");
        }
        
        // Create decryption context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) {
            EVP_PKEY_free(pkey);
            secure_zero_memory(private_key_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to create EVP_PKEY context");
        }
        
        // Initialize decryption
        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            secure_zero_memory(private_key_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to initialize RSA decryption");
        }
        
        // Set padding to OAEP
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            secure_zero_memory(private_key_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to set RSA OAEP padding");
        }
        
        // Determine buffer size
        size_t decrypted_len = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &decrypted_len, encrypted_dek.data(), encrypted_dek.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            secure_zero_memory(private_key_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to determine decrypted DEK size");
        }
        
        // Decrypt DEK
        std::vector<uint8_t> decrypted_dek(decrypted_len);
        if (EVP_PKEY_decrypt(ctx, decrypted_dek.data(), &decrypted_len, encrypted_dek.data(), encrypted_dek.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            secure_zero_memory(private_key_copy);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to decrypt DEK with RSA-OAEP");
        }
        
        decrypted_dek.resize(decrypted_len);
        
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        
        // Secure zero private key from memory after use
        secure_zero_memory(private_key_copy);
        
        return decrypted_dek;
        
    } catch (const FileException&) {
        secure_zero_memory(private_key_copy);
        throw;
    } catch (const std::exception& e) {
        secure_zero_memory(private_key_copy);
        throw FileException(FileError::DECRYPTION_FAILED, 
                          std::string("RSA DEK decryption failed: ") + e.what());
    }
}

std::string FileEncryptionEngine::encrypt_metadata(
    const std::string& data,
    const std::vector<uint8_t>& mek) {
    
    if (mek.empty()) {
        throw FileException(FileError::INVALID_DEK, "MEK cannot be empty for metadata encryption");
    }
    
    if (data.empty()) {
        return "";  // Empty data, return empty string
    }
    
    try {
        // Generate random IV for AES-256-GCM (96 bits = 12 bytes)
        std::vector<uint8_t> iv = generate_random_bytes(12);
        
        // Convert string to bytes
        std::vector<uint8_t> plaintext_data(data.begin(), data.end());
        
        // Encrypt data using AES-256-GCM with MEK
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to create EVP context");
        }
        
        // Initialize encryption with AES-256-GCM
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to initialize AES-256-GCM");
        }
        
        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to set IV length");
        }
        
        // Initialize key and IV
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, mek.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to set key and IV");
        }
        
        // Encrypt the data
        std::vector<uint8_t> encrypted_data(plaintext_data.size());
        int len = 0;
        int encrypted_len = 0;
        
        if (EVP_EncryptUpdate(ctx, encrypted_data.data(), &len, plaintext_data.data(), static_cast<int>(plaintext_data.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to encrypt metadata");
        }
        encrypted_len = len;
        
        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, encrypted_data.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to finalize metadata encryption");
        }
        encrypted_len += len;
        encrypted_data.resize(encrypted_len);
        
        // Get authentication tag
        std::vector<uint8_t> auth_tag(16);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, auth_tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to get authentication tag");
        }
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Prepend IV to encrypted data, append auth tag
        std::vector<uint8_t> final_data;
        final_data.insert(final_data.end(), iv.begin(), iv.end());
        final_data.insert(final_data.end(), encrypted_data.begin(), encrypted_data.end());
        final_data.insert(final_data.end(), auth_tag.begin(), auth_tag.end());
        
        // Encode as base64 using OpenSSL
        BIO* bio_mem = BIO_new(BIO_s_mem());
        BIO* bio_b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
        bio_b64 = BIO_push(bio_b64, bio_mem);
        
        BIO_write(bio_b64, final_data.data(), static_cast<int>(final_data.size()));
        BIO_flush(bio_b64);
        
        char* encoded_data = nullptr;
        long encoded_len = BIO_get_mem_data(bio_mem, &encoded_data);
        
        std::string base64_result(encoded_data, encoded_len);
        
        BIO_free_all(bio_b64);
        
        return base64_result;
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::ENCRYPTION_FAILED, 
                          std::string("Metadata encryption failed: ") + e.what());
    }
}

std::string FileEncryptionEngine::decrypt_metadata(
    const std::string& encrypted_data,
    const std::vector<uint8_t>& mek) {
    
    if (mek.empty()) {
        throw FileException(FileError::INVALID_DEK, "MEK cannot be empty for metadata decryption");
    }
    
    if (encrypted_data.empty()) {
        return "";  // Empty data, return empty string
    }
    
    try {
        // Decode base64 encrypted_data using OpenSSL
        BIO* bio_mem = BIO_new_mem_buf(encrypted_data.c_str(), static_cast<int>(encrypted_data.length()));
        BIO* bio_b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
        bio_b64 = BIO_push(bio_b64, bio_mem);
        
        // Read decoded data
        std::vector<uint8_t> decoded_data(encrypted_data.length());  // Over-allocate
        int decoded_len = BIO_read(bio_b64, decoded_data.data(), static_cast<int>(decoded_data.size()));
        BIO_free_all(bio_b64);
        
        if (decoded_len <= 0) {
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to decode base64 metadata");
        }
        
        decoded_data.resize(decoded_len);
        
        // Extract IV from beginning of data (12 bytes)
        if (decoded_data.size() < 12 + 16) {  // IV + auth tag minimum
            throw FileException(FileError::DECRYPTION_FAILED, "Decoded metadata too short");
        }
        
        std::vector<uint8_t> iv(decoded_data.begin(), decoded_data.begin() + 12);
        
        // Extract auth tag from end (16 bytes)
        std::vector<uint8_t> auth_tag(decoded_data.end() - 16, decoded_data.end());
        
        // Extract encrypted content (between IV and auth tag)
        std::vector<uint8_t> encrypted_content(decoded_data.begin() + 12, decoded_data.end() - 16);
        
        // Decrypt remaining data using AES-256-GCM with MEK and IV
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to create EVP context");
        }
        
        // Initialize decryption with AES-256-GCM
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to initialize AES-256-GCM");
        }
        
        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to set IV length");
        }
        
        // Initialize key and IV
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, mek.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to set key and IV");
        }
        
        // Decrypt the data
        std::vector<uint8_t> decrypted_data(encrypted_content.size());
        int len = 0;
        int decrypted_len = 0;
        
        if (EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, encrypted_content.data(), static_cast<int>(encrypted_content.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to decrypt metadata");
        }
        decrypted_len = len;
        
        // Set authentication tag for verification
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(auth_tag.size()), auth_tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::DECRYPTION_FAILED, "Failed to set authentication tag");
        }
        
        // Finalize decryption and verify authentication tag
        if (EVP_DecryptFinal_ex(ctx, decrypted_data.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw FileException(FileError::DECRYPTION_FAILED, "Authentication verification failed for metadata");
        }
        decrypted_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        decrypted_data.resize(decrypted_len);
        
        // Convert bytes back to string
        return std::string(decrypted_data.begin(), decrypted_data.end());
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::DECRYPTION_FAILED, 
                          std::string("Metadata decryption failed: ") + e.what());
    }
}

std::string FileEncryptionEngine::generate_share_grant_hmac(
    const FileShareRequest& request,
    const std::vector<uint8_t>& mek) {
    
    if (mek.empty()) {
        throw FileException(FileError::INVALID_DEK, "MEK cannot be empty for HMAC generation");
    }
    
    try {
        // Create canonical string from FileShareRequest fields
        // Include file_id, recipient_username, encrypted_data_key, expires_at
        std::stringstream canonical_string;
        canonical_string << request.file_id << "|"
                        << request.recipient_username << "|";
        
        // Convert encrypted_data_key to hex string for canonical representation
        for (const auto& byte : request.encrypted_data_key) {
            canonical_string << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
        }
        canonical_string << "|";
        
        // Add expires_at (0 if not set)
        if (request.expires_at.has_value()) {
            canonical_string << request.expires_at.value();
        } else {
            canonical_string << "0";
        }
        
        std::string canonical_data = canonical_string.str();
        
        // Calculate HMAC-SHA256 using MEK as key
        unsigned char hmac_result[EVP_MAX_MD_SIZE];
        unsigned int hmac_len = 0;
        
        unsigned char* result = HMAC(EVP_sha256(), 
                                    mek.data(), static_cast<int>(mek.size()),
                                    reinterpret_cast<const unsigned char*>(canonical_data.c_str()), canonical_data.length(),
                                    hmac_result, &hmac_len);
        
        if (!result) {
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to calculate share grant HMAC");
        }
        
        // Convert HMAC to hex string (64 characters)
        std::stringstream hex_stream;
        hex_stream << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < hmac_len; ++i) {
            hex_stream << std::setw(2) << static_cast<unsigned>(hmac_result[i]);
        }
        
        return hex_stream.str();
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::ENCRYPTION_FAILED, 
                          std::string("Share grant HMAC generation failed: ") + e.what());
    }
}

std::string FileEncryptionEngine::generate_share_chain_hmac(
    const std::string& file_id,
    const std::string& recipient_username,
    const std::vector<uint8_t>& mek) {
    
    if (mek.empty()) {
        throw FileException(FileError::INVALID_DEK, "MEK cannot be empty for HMAC generation");
    }
    
    try {
        // Create canonical string from file_id and recipient_username
        std::string canonical_data = file_id + "|" + recipient_username;
        
        // Calculate HMAC-SHA256 using MEK as key
        unsigned char hmac_result[EVP_MAX_MD_SIZE];
        unsigned int hmac_len = 0;
        
        unsigned char* result = HMAC(EVP_sha256(), 
                                    mek.data(), static_cast<int>(mek.size()),
                                    reinterpret_cast<const unsigned char*>(canonical_data.c_str()), canonical_data.length(),
                                    hmac_result, &hmac_len);
        
        if (!result) {
            throw FileException(FileError::ENCRYPTION_FAILED, "Failed to calculate share chain HMAC");
        }
        
        // Convert HMAC to hex string (64 characters)
        std::stringstream hex_stream;
        hex_stream << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < hmac_len; ++i) {
            hex_stream << std::setw(2) << static_cast<unsigned>(hmac_result[i]);
        }
        
        return hex_stream.str();
        
    } catch (const FileException&) {
        throw;
    } catch (const std::exception& e) {
        throw FileException(FileError::ENCRYPTION_FAILED, 
                          std::string("Share chain HMAC generation failed: ") + e.what());
    }
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
        std::vector<uint8_t> compressed_data;
        
        // Use CompressionEngine directly based on content type
        if constexpr (std::is_same_v<ContentType, FileContent>) {
            // Individual file: compress file data with zlib
            compressed_data = compression_engine_->compress_data(content_data.file_data);
        } else if constexpr (std::is_same_v<ContentType, FolderContent>) {
            // Folder: create ZIP archive with libzip (no compression in ZIP, we compress the ZIP bytes)
            compressed_data = compression_engine_->create_zip_archive(content_data);
        } else {
            throw FileException(FileError::INVALID_CONTENT_TYPE, "Unsupported content type");
        }
        
        // Encrypt compressed data using existing encrypt_file method
        FileEncryptionContext context = encrypt_file(compressed_data, mek);
        
        // Update context with content type and compression info
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
        // Decrypt encrypted_data using existing decrypt_file method
        std::vector<uint8_t> compressed_data = decrypt_file(encrypted_data, context);
        
        // Decompress/extract data using compression_engine_ based on content type
        if constexpr (std::is_same_v<ContentType, FileContent>) {
            if (context.content_type != ContentTypeEnum::FILE) {
                throw FileException(FileError::INVALID_CONTENT_TYPE, "Content type mismatch: expected FILE");
            }
            
            // For files: decompress zlib compressed data
            std::vector<uint8_t> file_data;
            if (context.is_compressed) {
                file_data = compression_engine_->decompress_data(compressed_data);
            } else {
                file_data = compressed_data;
            }
            
            // Create FileContent from decompressed data
            FileContent file_content;
            file_content.file_data = file_data;
            file_content.original_size = file_data.size();
            // Note: filename and metadata would need to be restored from context or separately stored
            
            return file_content;
            
        } else if constexpr (std::is_same_v<ContentType, FolderContent>) {
            if (context.content_type != ContentTypeEnum::FOLDER) {
                throw FileException(FileError::INVALID_CONTENT_TYPE, "Content type mismatch: expected FOLDER");
            }
            
            // For folders: extract ZIP archive (compressed_data is the ZIP bytes)
            return compression_engine_->extract_zip_archive(compressed_data);
            
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