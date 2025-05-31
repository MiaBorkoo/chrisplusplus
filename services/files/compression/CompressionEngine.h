#pragma once

#include "../exceptions/Exceptions.h"
#include <vector>
#include <cstdint>
#include <string>
#include <map>

// Forward declarations for content types
struct FileContent {
    std::string filename;
    std::vector<uint8_t> file_data;
    std::map<std::string, std::string> metadata;
    size_t original_size;
};

struct FolderContent {
    std::string folder_name;
    std::map<std::string, FileContent> files;  // relative_path -> FileContent
    std::map<std::string, FolderContent> subfolders;  // subfolder_name -> FolderContent
    std::map<std::string, std::string> metadata;
    size_t total_size;
    size_t file_count;
};

class CompressionEngine {
public:
    CompressionEngine();
    ~CompressionEngine() = default;

    // ZIP archive operations using libzip (for folders)
    std::vector<uint8_t> create_zip_archive(const FolderContent& folder_content);
    FolderContent extract_zip_archive(const std::vector<uint8_t>& zip_data);
    
    // File system I/O helpers
    FileContent load_file_content(const std::string& filepath);
    FolderContent load_folder_content(const std::string& folder_path);
    void save_file_content(const FileContent& file_content, const std::string& output_path);
    void save_folder_content(const FolderContent& folder_content, const std::string& output_directory);

    // zlib compression/decompression (for individual files)
    std::vector<uint8_t> compress_data(
        const std::vector<uint8_t>& data,
        int compression_level = 6);
    
    std::vector<uint8_t> decompress_data(
        const std::vector<uint8_t>& compressed_data);
    
    // Format detection and utility functions
    bool is_zip_archive(const std::vector<uint8_t>& data);
    bool is_compressed(const std::vector<uint8_t>& data);
    size_t estimate_compressed_size(size_t original_size);
    size_t estimate_zip_size(const FolderContent& folder_content);
    double get_compression_ratio(size_t original_size, size_t compressed_size);
    
    // Validation function
    bool validate_compression_level(int level);

private:
    // Internal zlib helpers
    void cleanup_zlib_stream(void* stream);
    
    // Internal libzip helpers
    void add_file_to_zip(void* zip_archive, const std::string& path, const FileContent& file);
    void add_folder_to_zip(void* zip_archive, const std::string& base_path, const FolderContent& folder);
    FileContent extract_file_from_zip(void* zip_archive, const std::string& path);
    std::string normalize_zip_path(const std::string& path);
}; 