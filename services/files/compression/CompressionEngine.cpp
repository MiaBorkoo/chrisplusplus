#include "CompressionEngine.h"
#include "../exceptions/Exceptions.h"
#include <zlib.h>
#include <stdexcept>
#include <algorithm>

CompressionEngine::CompressionEngine() {
    // Initialize zlib if needed
}

std::vector<uint8_t> CompressionEngine::compress_data(
    const std::vector<uint8_t>& data,
    int compression_level) {
    
    if (data.empty()) {
        return data;  // Nothing to compress
    }
    
    if (!validate_compression_level(compression_level)) {
        compression_level = 6;  // Default to standard compression
    }
    
    try {
        z_stream stream = {};
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.opaque = Z_NULL;
        
        if (deflateInit2(&stream, compression_level, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
            throw std::runtime_error("Failed to initialize deflate");
        }
        
        size_t output_size = compressBound(data.size());
        std::vector<uint8_t> output(output_size);
        
        stream.avail_in = data.size();
        stream.next_in = const_cast<uint8_t*>(data.data());
        stream.avail_out = output.size();
        stream.next_out = output.data();
        
        int result = deflate(&stream, Z_FINISH);
        
        if (result != Z_STREAM_END) {
            deflateEnd(&stream);
            throw std::runtime_error("Deflate failed: " + std::to_string(result));
        }
        
        output.resize(stream.total_out);
        deflateEnd(&stream);
        
        return output;
        
    } catch (const std::exception& e) {
        throw FileException(FileError::COMPRESSION_FAILED, 
                          std::string("Compression failed: ") + e.what());
    }
}

std::vector<uint8_t> CompressionEngine::decompress_data(
    const std::vector<uint8_t>& compressed_data) {
    
    if (compressed_data.empty()) {
        return compressed_data;  // Nothing to decompress
    }
    
    try {
        z_stream stream = {};
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.opaque = Z_NULL;
        
        if (inflateInit2(&stream, 15) != Z_OK) {
            throw std::runtime_error("Failed to initialize inflate");
        }
        
        size_t output_size = compressed_data.size() * 4;
        std::vector<uint8_t> output(output_size);
        
        stream.avail_in = compressed_data.size();
        stream.next_in = const_cast<uint8_t*>(compressed_data.data());
        
        int result;
        do {
            stream.avail_out = output.size() - stream.total_out;
            stream.next_out = output.data() + stream.total_out;
            
            result = inflate(&stream, Z_NO_FLUSH);
            
            if (result == Z_NEED_DICT || result == Z_DATA_ERROR || result == Z_MEM_ERROR) {
                inflateEnd(&stream);
                throw std::runtime_error("Inflate failed: " + std::to_string(result));
            }
            
            if (result != Z_STREAM_END && stream.avail_out == 0) {
                output.resize(output.size() * 2);
            }
            
        } while (result != Z_STREAM_END);
        
        output.resize(stream.total_out);
        inflateEnd(&stream);
        
        return output;
        
    } catch (const std::exception& e) {
        throw FileException(FileError::DECOMPRESSION_FAILED,
                          std::string("Decompression failed: ") + e.what());
    }
}

bool CompressionEngine::is_compressed(const std::vector<uint8_t>& data) {
    if (data.size() < 2) {
        return false;
    }
    
    // Check for zlib magic bytes
    uint8_t first = data[0];
    uint8_t second = data[1];
    
    // zlib format starts with 0x78 followed by various compression info bytes
    return (first == 0x78) && ((second == 0x01) || (second == 0x5E) || 
                               (second == 0x9C) || (second == 0xDA));
}

size_t CompressionEngine::estimate_compressed_size(size_t original_size) {
    return compressBound(original_size);
}

double CompressionEngine::get_compression_ratio(size_t original_size, size_t compressed_size) {
    if (original_size == 0) {
        return 1.0;
    }
    return static_cast<double>(compressed_size) / static_cast<double>(original_size);
}

bool CompressionEngine::validate_compression_level(int level) {
    // zlib compression levels: 0 (no compression) to 9 (max compression)
    return (level >= 0 && level <= 9);
}

void CompressionEngine::cleanup_zlib_stream(void* stream) {
    if (!stream) {
        return;
    }
    
    z_stream* zstream = static_cast<z_stream*>(stream);
    
    // Try both deflateEnd and inflateEnd since we don't know which type
    // One will fail, but that's expected
    deflateEnd(zstream);
    inflateEnd(zstream);
} 