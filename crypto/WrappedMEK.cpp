#include "WrappedMEK.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

EncryptedMEK encryptMEKWithWrapperKey(
    const std::vector<uint8_t>& mek,
    const std::vector<uint8_t>& mekWrapperKey
) {
    if (mekWrapperKey.size() != 32) {
        throw std::invalid_argument("MEK Wrapper Key must be 32 bytes (256 bits)");
    }

    EncryptedMEK encrypted;

    //generate a 12-byte iv (nonce) for aes-gcm
    encrypted.iv.resize(12);
    if (RAND_bytes(encrypted.iv.data(), (int)encrypted.iv.size()) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }

    //creating the encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    int len = 0;
    int ciphertext_len = 0;

    //allocating ciphertext buffer same size as MEK 
    encrypted.ciphertext.resize(mek.size());

    //initialise encryption context for AES-256-GCM -> no key or IV yet
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    //set IV length to 12 bytes
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)encrypted.iv.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl failed to set IV length");
    }

     //set the actual encryption key and iv values
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, mekWrapperKey.data(), encrypted.iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed to set key and IV");
    }

    // Encrypt the MEK
    if (EVP_EncryptUpdate(ctx, encrypted.ciphertext.data(), &len, mek.data(), (int)mek.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;

    // Finalise Encryption 
    if (EVP_EncryptFinal_ex(ctx, encrypted.ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;

    //resize ciphertext to actual written length
    encrypted.ciphertext.resize(ciphertext_len);

    //get the 16-byte authentication tag used for integrity verification
    encrypted.tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, encrypted.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get GCM tag");
    }


    EVP_CIPHER_CTX_free(ctx);

    return encrypted;
}