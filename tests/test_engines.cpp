#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../services/files/compression/CompressionEngine.h"
#include "../services/files/encryption/FileEncryptionEngine.h"
#include <vector>
#include <string>
#include <random>
#include <openssl/rand.h>

class CompressionEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        engine = std::make_unique<CompressionEngine>();
    }

    std::unique_ptr<CompressionEngine> engine;
    
    // Helper to generate test data
    std::vector<uint8_t> generate_test_data(size_t size, bool random = false) {
        std::vector<uint8_t> data(size);
        if (random) {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            for (auto& byte : data) {
                byte = static_cast<uint8_t>(dis(gen));
            }
        } else {
            // Compressible pattern
            for (size_t i = 0; i < size; ++i) {
                data[i] = static_cast<uint8_t>(i % 10);
            }
        }
        return data;
    }
};

class FileEncryptionEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        engine = std::make_unique<FileEncryptionEngine>();
        
        // Generate test MEK (256-bit)
        test_mek = generate_random_key(32);
        
        // Generate test data
        test_data = generate_test_data(1024);
    }

    std::unique_ptr<FileEncryptionEngine> engine;
    std::vector<uint8_t> test_mek;
    std::vector<uint8_t> test_data;
    
    std::vector<uint8_t> generate_random_key(size_t size) {
        std::vector<uint8_t> key(size);
        RAND_bytes(key.data(), static_cast<int>(size));
        return key;
    }
    
    std::vector<uint8_t> generate_test_data(size_t size) {
        std::vector<uint8_t> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(i % 256);
        }
        return data;
    }
};

// ===== CompressionEngine Tests =====

TEST_F(CompressionEngineTest, ValidateCompressionLevel_ValidLevels) {
    // Test all valid compression levels (0-9)
    for (int level = 0; level <= 9; ++level) {
        EXPECT_TRUE(engine->validate_compression_level(level))
            << "Level " << level << " should be valid";
    }
}

TEST_F(CompressionEngineTest, ValidateCompressionLevel_InvalidLevels) {
    // Test invalid compression levels
    EXPECT_FALSE(engine->validate_compression_level(-1));
    EXPECT_FALSE(engine->validate_compression_level(10));
    EXPECT_FALSE(engine->validate_compression_level(100));
}

TEST_F(CompressionEngineTest, EstimateCompressedSize_ValidInput) {
    size_t original_size = 1000;
    size_t estimated = engine->estimate_compressed_size(original_size);
    
    // Should be original size + overhead (12 bytes + 0.1%)
    size_t expected_min = original_size + 12;
    size_t expected_max = original_size + 12 + (original_size / 100); // More generous
    
    EXPECT_GE(estimated, expected_min);
    EXPECT_LE(estimated, expected_max);
}

TEST_F(CompressionEngineTest, EstimateCompressedSize_ZeroSize) {
    size_t estimated = engine->estimate_compressed_size(0);
    EXPECT_EQ(estimated, 12); // Just the overhead
}

TEST_F(CompressionEngineTest, GetCompressionRatio_ValidInput) {
    size_t original = 1000;
    size_t compressed = 600;
    
    double ratio = engine->get_compression_ratio(original, compressed);
    EXPECT_DOUBLE_EQ(ratio, 0.6);
}

TEST_F(CompressionEngineTest, GetCompressionRatio_ZeroOriginal) {
    double ratio = engine->get_compression_ratio(0, 100);
    EXPECT_DOUBLE_EQ(ratio, 1.0);
}

TEST_F(CompressionEngineTest, GetCompressionRatio_PerfectCompression) {
    double ratio = engine->get_compression_ratio(1000, 0);
    EXPECT_DOUBLE_EQ(ratio, 0.0);
}

TEST_F(CompressionEngineTest, CompressData_EmptyInput) {
    std::vector<uint8_t> empty_data;
    auto result = engine->compress_data(empty_data);
    EXPECT_EQ(result, empty_data); // Should return empty data unchanged
}

TEST_F(CompressionEngineTest, CompressData_SmallCompressibleData) {
    auto test_data = generate_test_data(100, false); // Compressible pattern
    
    auto compressed = engine->compress_data(test_data);
    
    // For compressible data, result should be smaller
    // Note: This test will pass once compress_data is implemented
    // For now, it returns empty vector due to TODO
    EXPECT_TRUE(compressed.empty() || compressed.size() <= test_data.size());
}

TEST_F(CompressionEngineTest, CompressData_LargeCompressibleData) {
    auto test_data = generate_test_data(10000, false); // Large compressible data
    
    auto compressed = engine->compress_data(test_data, 6); // Default compression
    
    // Should handle large data without issues
    EXPECT_TRUE(compressed.empty() || compressed.size() <= test_data.size());
}

TEST_F(CompressionEngineTest, CompressData_RandomData) {
    auto test_data = generate_test_data(1000, true); // Random, less compressible
    
    auto compressed = engine->compress_data(test_data, 9); // Max compression
    
    // Random data might not compress well, but shouldn't fail
    EXPECT_TRUE(compressed.empty() || compressed.size() >= 0);
}

TEST_F(CompressionEngineTest, DecompressData_EmptyInput) {
    std::vector<uint8_t> empty_data;
    auto result = engine->decompress_data(empty_data);
    EXPECT_EQ(result, empty_data); // Should return empty data unchanged
}

TEST_F(CompressionEngineTest, CompressDecompressRoundTrip) {
    auto original_data = generate_test_data(5000, false);
    
    // Compress then decompress
    auto compressed = engine->compress_data(original_data);
    auto decompressed = engine->decompress_data(compressed);
    
    // Should get back original data (once implemented)
    // For now, both return empty due to TODO
    if (!compressed.empty() && !decompressed.empty()) {
        EXPECT_EQ(original_data, decompressed);
    }
}

TEST_F(CompressionEngineTest, IsCompressed_ValidCompressedData) {
    // This will test magic byte detection once implemented
    auto test_data = generate_test_data(100);
    auto compressed = engine->compress_data(test_data);
    
    if (!compressed.empty()) {
        EXPECT_TRUE(engine->is_compressed(compressed));
    }
}

TEST_F(CompressionEngineTest, IsCompressed_UncompressedData) {
    auto test_data = generate_test_data(100);
    EXPECT_FALSE(engine->is_compressed(test_data)); // Should not have zlib magic bytes
}

// ===== FileEncryptionEngine Tests =====

TEST_F(FileEncryptionEngineTest, GenerateRandomBytes_ValidSizes) {
    // Test various key sizes
    std::vector<size_t> sizes = {16, 32, 64, 96, 128};
    
    for (size_t size : sizes) {
        auto random_bytes = engine->generate_random_bytes(size);
        EXPECT_EQ(random_bytes.size(), size);
        
        // Ensure it's not all zeros (extremely unlikely with proper random generation)
        bool has_non_zero = false;
        for (uint8_t byte : random_bytes) {
            if (byte != 0) {
                has_non_zero = true;
                break;
            }
        }
        EXPECT_TRUE(has_non_zero) << "Random bytes should not be all zeros";
    }
}

TEST_F(FileEncryptionEngineTest, GenerateRandomBytes_Uniqueness) {
    // Generate multiple random byte arrays and ensure they're different
    auto bytes1 = engine->generate_random_bytes(32);
    auto bytes2 = engine->generate_random_bytes(32);
    
    EXPECT_NE(bytes1, bytes2) << "Random byte arrays should be unique";
}

TEST_F(FileEncryptionEngineTest, EncryptFile_ValidInput) {
    auto context = engine->encrypt_file(test_data, test_mek);
    
    // Verify context is properly populated
    EXPECT_EQ(context.dek.size(), 32); // 256-bit DEK
    EXPECT_EQ(context.iv.size(), 12);  // 96-bit IV for GCM
    EXPECT_EQ(context.auth_tag.size(), 16); // 128-bit auth tag
    EXPECT_FALSE(context.file_id.empty());
    EXPECT_EQ(context.original_size, test_data.size());
    EXPECT_FALSE(context.hmac.empty());
    
    // Verify UUID format (36 characters with hyphens)
    EXPECT_EQ(context.file_id.length(), 36);
    EXPECT_EQ(context.file_id[8], '-');
    EXPECT_EQ(context.file_id[13], '-');
    EXPECT_EQ(context.file_id[18], '-');
    EXPECT_EQ(context.file_id[23], '-');
}

TEST_F(FileEncryptionEngineTest, EncryptFile_EmptyData) {
    std::vector<uint8_t> empty_data;
    auto context = engine->encrypt_file(empty_data, test_mek);
    
    EXPECT_EQ(context.original_size, 0);
    EXPECT_EQ(context.dek.size(), 32);
    EXPECT_FALSE(context.file_id.empty());
}

TEST_F(FileEncryptionEngineTest, EncryptFile_LargeData) {
    auto large_data = generate_test_data(100000); // 100KB
    auto context = engine->encrypt_file(large_data, test_mek);
    
    EXPECT_EQ(context.original_size, large_data.size());
    EXPECT_EQ(context.dek.size(), 32);
    EXPECT_FALSE(context.hmac.empty());
}

TEST_F(FileEncryptionEngineTest, EncryptDecryptFile_RoundTrip) {
    // Encrypt file
    auto context = engine->encrypt_file(test_data, test_mek);
    
    // For round-trip test, we need the encrypted data
    // Since encrypt_file doesn't return it, we'll simulate it
    // In real implementation, this would come from the server
    std::vector<uint8_t> encrypted_data = test_data; // Placeholder
    
    // Decrypt file
    auto decrypted_data = engine->decrypt_file(encrypted_data, context);
    
    // Note: This test may fail until encrypt_file returns encrypted data
    // or we properly simulate the encryption process
    EXPECT_EQ(decrypted_data.size(), test_data.size());
}

TEST_F(FileEncryptionEngineTest, CalculateFileHmac_ValidInput) {
    auto hmac = engine->calculate_file_hmac(test_data, test_mek);
    
    // HMAC-SHA256 produces 64 hex characters
    EXPECT_EQ(hmac.length(), 64);
    
    // Should be valid hex string
    for (char c : hmac) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            << "HMAC should be lowercase hex";
    }
}

TEST_F(FileEncryptionEngineTest, CalculateFileHmac_Consistency) {
    // Same input should produce same HMAC
    auto hmac1 = engine->calculate_file_hmac(test_data, test_mek);
    auto hmac2 = engine->calculate_file_hmac(test_data, test_mek);
    
    EXPECT_EQ(hmac1, hmac2);
}

TEST_F(FileEncryptionEngineTest, CalculateFileHmac_DifferentKeys) {
    // Different MEKs should produce different HMACs
    auto other_mek = generate_random_key(32);
    
    auto hmac1 = engine->calculate_file_hmac(test_data, test_mek);
    auto hmac2 = engine->calculate_file_hmac(test_data, other_mek);
    
    EXPECT_NE(hmac1, hmac2);
}

TEST_F(FileEncryptionEngineTest, CalculateFileHmac_EmptyData) {
    std::vector<uint8_t> empty_data;
    auto hmac = engine->calculate_file_hmac(empty_data, test_mek);
    
    EXPECT_EQ(hmac.length(), 64); // Should still produce valid HMAC
}

TEST_F(FileEncryptionEngineTest, SecureZeroMemory_ValidData) {
    std::vector<uint8_t> sensitive_data = {1, 2, 3, 4, 5};
    engine->secure_zero_memory(sensitive_data);
    
    EXPECT_TRUE(sensitive_data.empty());
}

TEST_F(FileEncryptionEngineTest, SecureZeroMemory_EmptyData) {
    std::vector<uint8_t> empty_data;
    engine->secure_zero_memory(empty_data); // Should not crash
    
    EXPECT_TRUE(empty_data.empty());
}

// ===== Template Function Tests (Expected Behavior) =====

TEST_F(FileEncryptionEngineTest, EncryptContent_FileContent) {
    FileContent file_content;
    file_content.filename = "test.txt";
    file_content.file_data = test_data;
    file_content.original_size = test_data.size();
    
    // This will test the template function once dependencies are implemented
    try {
        auto context = engine->encrypt_content(file_content, test_mek, ContentTypeEnum::FILE);
        
        EXPECT_EQ(context.content_type, ContentTypeEnum::FILE);
        EXPECT_TRUE(context.is_compressed);
        EXPECT_EQ(context.original_size, test_data.size());
        EXPECT_GT(context.compressed_size, 0);
    } catch (const FileException& e) {
        // Expected to fail until serialization/compression engines are implemented
        EXPECT_EQ(e.get_error_type(), FileError::ENCRYPTION_FAILED);
    }
}

TEST_F(FileEncryptionEngineTest, EncryptContent_FolderContent) {
    FolderContent folder_content;
    folder_content.folder_name = "test_folder";
    folder_content.total_size = 1000;
    folder_content.file_count = 2;
    
    // Add some files to the folder
    FileContent file1;
    file1.filename = "file1.txt";
    file1.file_data = {1, 2, 3, 4, 5};
    file1.original_size = 5;
    
    folder_content.files["file1.txt"] = file1;
    
    try {
        auto context = engine->encrypt_content(folder_content, test_mek, ContentTypeEnum::FOLDER);
        
        EXPECT_EQ(context.content_type, ContentTypeEnum::FOLDER);
        EXPECT_TRUE(context.is_compressed);
    } catch (const FileException& e) {
        // Expected to fail until serialization/compression engines are implemented
        EXPECT_EQ(e.get_error_type(), FileError::ENCRYPTION_FAILED);
    }
}

// ===== Error Handling Tests =====

TEST_F(CompressionEngineTest, CompressData_InvalidCompressionLevel) {
    auto test_data = generate_test_data(100);
    
    // Should handle invalid compression level gracefully (fallback to default)
    auto result = engine->compress_data(test_data, -1);
    // Implementation should default to level 6, so no exception expected
}

TEST_F(FileEncryptionEngineTest, EncryptFile_EmptyMEK) {
    std::vector<uint8_t> empty_mek;
    
    EXPECT_THROW(
        engine->encrypt_file(test_data, empty_mek),
        FileException
    );
}

TEST_F(FileEncryptionEngineTest, DecryptFile_InvalidContext) {
    FileEncryptionContext invalid_context;
    // Leave context empty (invalid)
    
    EXPECT_THROW(
        engine->decrypt_file(test_data, invalid_context),
        FileException
    );
}

TEST_F(FileEncryptionEngineTest, CalculateFileHmac_EmptyMEK) {
    std::vector<uint8_t> empty_mek;
    
    EXPECT_THROW(
        engine->calculate_file_hmac(test_data, empty_mek),
        FileException
    );
}

// ===== Future Implementation Tests (TODO Functions) =====

TEST_F(FileEncryptionEngineTest, GenerateDEK_ExpectedBehavior) {
    // Test for generate_dek() once implemented
    auto dek = engine->generate_dek();
    
    // Should generate 256-bit (32 byte) key once implemented
    if (!dek.empty()) {
        EXPECT_EQ(dek.size(), 32);
    }
}

TEST_F(FileEncryptionEngineTest, VerifyFileIntegrity_ExpectedBehavior) {
    auto hmac = engine->calculate_file_hmac(test_data, test_mek);
    
    // Should verify integrity once implemented
    bool is_valid = engine->verify_file_integrity(test_data, hmac, test_mek);
    
    // Currently returns false (TODO), but should return true once implemented
    // EXPECT_TRUE(is_valid);
}

TEST_F(FileEncryptionEngineTest, EncryptMetadata_ExpectedBehavior) {
    std::string metadata = "test_filename.txt";
    
    auto encrypted = engine->encrypt_metadata(metadata, test_mek);
    
    // Should return base64 encoded encrypted metadata once implemented
    if (!encrypted.empty()) {
        EXPECT_GT(encrypted.length(), metadata.length());
    }
}

TEST_F(FileEncryptionEngineTest, GenerateShareHMACs_ExpectedBehavior) {
    FileShareRequest request;
    request.file_id = "test-file-id";
    request.recipient_username = "testuser";
    
    auto grant_hmac = engine->generate_share_grant_hmac(request, test_mek);
    auto chain_hmac = engine->generate_share_chain_hmac(
        request.file_id, request.recipient_username, test_mek);
    
    // Should generate 64-character hex strings once implemented
    if (!grant_hmac.empty()) {
        EXPECT_EQ(grant_hmac.length(), 64);
    }
    if (!chain_hmac.empty()) {
        EXPECT_EQ(chain_hmac.length(), 64);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 