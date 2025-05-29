#pragma once

#include "../exceptions/Exceptions.h"
#include <vector>
#include <cstdint>
#include <string>
#include <map>

// Forward declare content structures
struct FileContent;
struct FolderContent;

class SerializationEngine {
public:
    SerializationEngine();
    ~SerializationEngine() = default;

    // File content serialization
    std::vector<uint8_t> serialize_file_content(const FileContent& file_content);
    FileContent deserialize_file_content(const std::vector<uint8_t>& serialized_data);
    
    // Folder content serialization  
    std::vector<uint8_t> serialize_folder_content(const FolderContent& folder_content);
    FolderContent deserialize_folder_content(const std::vector<uint8_t>& serialized_data);
    
    // Utility functions
    size_t estimate_serialized_size(const FileContent& content);
    size_t estimate_serialized_size(const FolderContent& content);
    bool validate_serialized_data(const std::vector<uint8_t>& data);

private:
    // Binary serialization helpers
    void write_string(std::vector<uint8_t>& buffer, const std::string& str);
    std::string read_string(const std::vector<uint8_t>& buffer, size_t& offset);
    
    void write_uint64(std::vector<uint8_t>& buffer, uint64_t value);
    uint64_t read_uint64(const std::vector<uint8_t>& buffer, size_t& offset);
    
    void write_uint32(std::vector<uint8_t>& buffer, uint32_t value);
    uint32_t read_uint32(const std::vector<uint8_t>& buffer, size_t& offset);
    
    void write_bytes(std::vector<uint8_t>& buffer, const std::vector<uint8_t>& data);
    std::vector<uint8_t> read_bytes(const std::vector<uint8_t>& buffer, size_t& offset);
    
    void write_metadata_map(std::vector<uint8_t>& buffer, 
                           const std::map<std::string, std::string>& metadata);
    std::map<std::string, std::string> read_metadata_map(
        const std::vector<uint8_t>& buffer, size_t& offset);
    
    // Validation helpers
    bool check_magic_header(const std::vector<uint8_t>& data, const std::string& expected);
    void write_magic_header(std::vector<uint8_t>& buffer, const std::string& magic);
    
    // Constants for binary format
    static constexpr const char* FILE_MAGIC = "FLCNT001";    // File Content v1
    static constexpr const char* FOLDER_MAGIC = "FLDCNT01";  // Folder Content v1
}; 