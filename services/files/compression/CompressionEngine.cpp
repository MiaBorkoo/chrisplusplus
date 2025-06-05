#include "CompressionEngine.h"
#include "../exceptions/Exceptions.h"
#include <zip.h>
#include <zlib.h>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <cstring>

CompressionEngine::CompressionEngine() {
    // Initialize libzip and zlib if needed
}

// ZIP archive operations using libzip

std::vector<uint8_t> CompressionEngine::create_zip_archive(const FolderContent& folder_content) {
    try {
        // Create in-memory ZIP archive
        zip_error_t error;
        zip_source_t* source = zip_source_buffer_create(nullptr, 0, 0, &error);
        if (!source) {
            throw std::runtime_error("Failed to create ZIP source");
        }
        
        zip_t* zip_archive = zip_open_from_source(source, ZIP_CREATE, &error);
        if (!zip_archive) {
            zip_source_free(source);
            throw std::runtime_error("Failed to create ZIP archive");
        }
        
        // Add folder contents recursively
        add_folder_to_zip(zip_archive, "", folder_content);
        
        // Write ZIP to memory buffer
        zip_source_t* final_source = zip_source_zip(zip_archive, zip_archive, 0, 0, 0, -1);
        if (!final_source) {
            zip_close(zip_archive);
            throw std::runtime_error("Failed to create final ZIP source");
        }
        
        // Get buffer size and allocate
        zip_stat_t stat;
        if (zip_source_stat(final_source, &stat) != 0) {
            zip_source_free(final_source);
            zip_close(zip_archive);
            throw std::runtime_error("Failed to get ZIP size");
        }
        
        std::vector<uint8_t> zip_data(stat.size);
        
        // Read ZIP data
        if (zip_source_open(final_source) != 0) {
            zip_source_free(final_source);
            zip_close(zip_archive);
            throw std::runtime_error("Failed to open ZIP source for reading");
        }
        
        zip_int64_t bytes_read = zip_source_read(final_source, zip_data.data(), zip_data.size());
        zip_source_close(final_source);
        zip_source_free(final_source);
        zip_close(zip_archive);
        
        if (bytes_read != static_cast<zip_int64_t>(zip_data.size())) {
            throw std::runtime_error("Failed to read complete ZIP data");
        }
        
        return zip_data;
        
    } catch (const std::exception& e) {
        throw FileException(FileError::COMPRESSION_FAILED,
                          std::string("ZIP creation failed: ") + e.what());
    }
}

FolderContent CompressionEngine::extract_zip_archive(const std::vector<uint8_t>& zip_data) {
    try {
        zip_error_t error;
        zip_source_t* source = zip_source_buffer_create(zip_data.data(), zip_data.size(), 0, &error);
        if (!source) {
            throw std::runtime_error("Failed to create ZIP source from buffer");
        }
        
        zip_t* zip_archive = zip_open_from_source(source, ZIP_RDONLY, &error);
        if (!zip_archive) {
            zip_source_free(source);
            throw std::runtime_error("Failed to open ZIP archive");
        }
        
        FolderContent root_folder;
        zip_int64_t num_entries = zip_get_num_entries(zip_archive, 0);
        
        for (zip_int64_t i = 0; i < num_entries; i++) {
            const char* name = zip_get_name(zip_archive, i, 0);
            if (!name) continue;
            
            std::string path(name);
            
            // Skip directories (they end with '/')
            if (path.back() == '/') {
                continue;
            }
            
            // Extract file
            FileContent file = extract_file_from_zip(zip_archive, path);
            
            // Add to appropriate location in folder structure
            std::filesystem::path file_path(path);
            if (file_path.has_parent_path()) {
                // TODO: Handle nested folder structure
                // For now, add all files to root
                root_folder.files[path] = file;
            } else {
                root_folder.files[path] = file;
            }
        }
        
        zip_close(zip_archive);
        
        // Calculate totals
        root_folder.total_size = 0;
        root_folder.file_count = root_folder.files.size();
        for (const auto& [path, file] : root_folder.files) {
            root_folder.total_size += file.original_size;
        }
        
        return root_folder;
        
    } catch (const std::exception& e) {
        throw FileException(FileError::DECOMPRESSION_FAILED,
                          std::string("ZIP extraction failed: ") + e.what());
    }
}

// File system I/O helpers

FileContent CompressionEngine::load_file_content(const std::string& filepath) {
    FileContent file_content;
    
    std::filesystem::path path(filepath);
    file_content.filename = path.filename().string();
    
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        throw FileException(FileError::FILE_NOT_FOUND, "Could not open file: " + filepath);
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Read file data
    file_content.file_data.resize(file_size);
    file.read(reinterpret_cast<char*>(file_content.file_data.data()), file_size);
    file_content.original_size = file_size;
    
    return file_content;
}

FolderContent CompressionEngine::load_folder_content(const std::string& folder_path) {
    FolderContent folder_content;
    
    std::filesystem::path path(folder_path);
    folder_content.folder_name = path.filename().string();
    folder_content.total_size = 0;
    folder_content.file_count = 0;
    
    for (const auto& entry : std::filesystem::recursive_directory_iterator(folder_path)) {
        if (entry.is_regular_file()) {
            std::string relative_path = std::filesystem::relative(entry.path(), folder_path).string();
            
            // Normalize path separators to forward slashes for ZIP compatibility
            std::replace(relative_path.begin(), relative_path.end(), '\\', '/');
            
            FileContent file = load_file_content(entry.path().string());
            folder_content.files[relative_path] = file;
            folder_content.total_size += file.original_size;
            folder_content.file_count++;
        }
    }
    
    return folder_content;
}

void CompressionEngine::save_file_content(const FileContent& file_content, const std::string& output_path) {
    std::ofstream file(output_path, std::ios::binary);
    if (!file) {
        throw FileException(FileError::INVALID_SESSION, "Could not create output file: " + output_path);
    }
    
    file.write(reinterpret_cast<const char*>(file_content.file_data.data()), file_content.file_data.size());
}

void CompressionEngine::save_folder_content(const FolderContent& folder_content, const std::string& output_directory) {
    std::filesystem::create_directories(output_directory);
    
    for (const auto& [relative_path, file] : folder_content.files) {
        std::filesystem::path output_file_path = std::filesystem::path(output_directory) / relative_path;
        
        // Create parent directories if needed
        std::filesystem::create_directories(output_file_path.parent_path());
        
        save_file_content(file, output_file_path.string());
    }
}

// Format detection functions

bool CompressionEngine::is_zip_archive(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        return false;
    }
    
    // Check for ZIP magic bytes (PK\x03\x04 or PK\x05\x06)
    return (data[0] == 0x50 && data[1] == 0x4B &&
            ((data[2] == 0x03 && data[3] == 0x04) ||
             (data[2] == 0x05 && data[3] == 0x06)));
}

size_t CompressionEngine::estimate_zip_size(const FolderContent& folder_content) {
    size_t estimated_size = 100; // ZIP headers and central directory
    
    for (const auto& [path, file] : folder_content.files) {
        estimated_size += path.length() + 50; // File entry headers
        estimated_size += file.original_size * 0.7; // Assume 30% compression
    }
    
    return estimated_size;
}

// Internal libzip helpers

void CompressionEngine::add_file_to_zip(void* zip_archive, const std::string& path, const FileContent& file) {
    zip_t* archive = static_cast<zip_t*>(zip_archive);
    
    zip_source_t* source = zip_source_buffer(archive, file.file_data.data(), file.file_data.size(), 0);
    if (!source) {
        throw std::runtime_error("Failed to create file source for: " + path);
    }
    
    std::string normalized_path = normalize_zip_path(path);
    zip_int64_t index = zip_file_add(archive, normalized_path.c_str(), source, ZIP_FL_OVERWRITE);
    if (index < 0) {
        zip_source_free(source);
        throw std::runtime_error("Failed to add file to ZIP: " + path);
    }
}

void CompressionEngine::add_folder_to_zip(void* zip_archive, const std::string& base_path, const FolderContent& folder) {
    for (const auto& [relative_path, file] : folder.files) {
        std::string full_path = base_path.empty() ? relative_path : base_path + "/" + relative_path;
        add_file_to_zip(zip_archive, full_path, file);
    }
    
    for (const auto& [subfolder_name, subfolder] : folder.subfolders) {
        std::string subfolder_path = base_path.empty() ? subfolder_name : base_path + "/" + subfolder_name;
        add_folder_to_zip(zip_archive, subfolder_path, subfolder);
    }
}

FileContent CompressionEngine::extract_file_from_zip(void* zip_archive, const std::string& path) {
    zip_t* archive = static_cast<zip_t*>(zip_archive);
    
    zip_file_t* file = zip_fopen(archive, path.c_str(), 0);
    if (!file) {
        throw std::runtime_error("Failed to open file in ZIP: " + path);
    }
    
    zip_stat_t stat;
    if (zip_stat(archive, path.c_str(), 0, &stat) != 0) {
        zip_fclose(file);
        throw std::runtime_error("Failed to get file stats: " + path);
    }
    
    FileContent file_content;
    file_content.filename = std::filesystem::path(path).filename().string();
    file_content.original_size = stat.size;
    file_content.file_data.resize(stat.size);
    
    zip_int64_t bytes_read = zip_fread(file, file_content.file_data.data(), stat.size);
    zip_fclose(file);
    
    if (bytes_read != static_cast<zip_int64_t>(stat.size)) {
        throw std::runtime_error("Failed to read complete file from ZIP: " + path);
    }
    
    return file_content;
}

std::string CompressionEngine::normalize_zip_path(const std::string& path) {
    std::string normalized = path;
    
    // Replace backslashes with forward slashes
    std::replace(normalized.begin(), normalized.end(), '\\', '/');
    
    // Remove leading slash if present
    if (!normalized.empty() && normalized[0] == '/') {
        normalized = normalized.substr(1);
    }
    
    return normalized;
}

// Existing zlib compression functions remain unchanged

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

void CompressionEngine::copyAndReverseArray(uint8_t* dest, const uint8_t* src, size_t length) {
    // Create pointers to start and end of source array
    const uint8_t* src_start = src;
    const uint8_t* src_end = src + length - 1;
    
    // Create pointer to destination array
    uint8_t* dest_ptr = dest;
    
    // Copy in reverse order using pointer arithmetic
    while (src_end >= src_start) {
        *dest_ptr = *src_end;  // Dereference pointers to access/modify array elements
        dest_ptr++;            // Move destination pointer forward
        src_end--;            // Move source pointer backward
    }
} 