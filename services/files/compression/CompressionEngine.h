#pragma once

#include "../exceptions/Exceptions.h"
#include <vector>
#include <cstdint>

class CompressionEngine {
public:
    CompressionEngine();
    ~CompressionEngine() = default;

    // Core compression/decompression using zlib
    std::vector<uint8_t> compress_data(
        const std::vector<uint8_t>& data,
        int compression_level = 6);
    
    std::vector<uint8_t> decompress_data(
        const std::vector<uint8_t>& compressed_data);
    
    // Utility functions
    bool is_compressed(const std::vector<uint8_t>& data);
    size_t estimate_compressed_size(size_t original_size);
    double get_compression_ratio(size_t original_size, size_t compressed_size);

private:
    // Internal zlib helpers
    bool validate_compression_level(int level);
    void cleanup_zlib_stream(void* stream);
}; 