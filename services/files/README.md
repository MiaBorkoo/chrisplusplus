# File Management System - Data Conversion Layer Implementation

## Overview

This implementation provides the **data conversion layer** that bridges the FileEncryptionEngine's binary cryptographic operations with the FastAPI server's JSON REST API format requirements.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ FileManager     │    │ HTTPClient       │    │ DataConverter   │
│ (High-level)    │◄──►│ (API Transport)  │◄──►│ (Format Bridge) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│FileEncryption   │    │ SSL HttpClient   │    │ Base64/JSON     │
│Engine (Crypto)  │    │ (Network Layer)  │    │ (Encoding)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## What Was Implemented

### 1. **DataConverter Class** (`network/DataConverter.{h,cpp}`)

**Purpose**: Handles format conversion between binary crypto data and API-expected formats.

**Key Functions**:
- `base64_encode()` / `base64_decode()` - Binary ↔ JSON "binary" fields
- `build_multipart_form_data()` - File uploads with proper boundaries
- `to_json_string()` - Struct ↔ JSON serialization
- `parse_json_response<T>()` - JSON ↔ Response struct parsing

**Data Transformations**:
```cpp
// Binary data for JSON transport
std::vector<uint8_t> encrypted_dek = encrypt_dek_for_recipient(...);
std::string api_dek = DataConverter::base64_encode(encrypted_dek);  // For JSON

// Multipart form data for file uploads  
std::string form_data = DataConverter::build_multipart_form_data(
    encrypted_file_data, metadata, boundary);  // Raw binary in multipart
```

### 2. **Complete HTTPClient Implementation** (`network/HTTPClient.{h,cpp}`)

**Purpose**: REST API client using existing SSL infrastructure.

**Features**:
- ✅ SSL/TLS transport via existing `httpC/HttpClient`
- ✅ Bearer token authentication 
- ✅ Multipart file uploads
- ✅ JSON request/response handling
- ✅ Proper error handling with FileException

**Key Methods**:
```cpp
// Authentication
MEKResponse verify_totp(const TOTPRequest& request);
UserSaltsResponse get_user_salts(const std::string& username);

// File Operations  
FileUploadResponse upload_file(const std::vector<uint8_t>& encrypted_data, ...);
FileDownloadResponse download_file(const std::string& file_id, ...);
FileShareResponse share_file(const FileShareRequest& request, ...);
```

### 3. **Format Compatibility**

**API Schema Compliance**:
```cpp
// Server expects (from fast_api_endpoints.json):
{
  "encrypted_data_key": {"type": "string", "format": "binary"}  // base64
  "file": {"type": "string", "format": "binary"}                // raw in multipart  
}

// Our conversion:
request.encrypted_data_key = DataConverter::base64_encode(dek_bytes);  // ✅
form.add_binary_field("file", encrypted_file_data);                   // ✅
```

## Integration Points

### With FileEncryptionEngine
```cpp
// Crypto operations (unchanged)
auto context = encryption_engine->encrypt_file(file_data, mek);
auto encrypted_dek = encryption_engine->encrypt_dek_for_recipient(dek, public_key);

// Format conversion (new)
FileUploadRequest api_request;
api_request.filename_encrypted = encryption_engine->encrypt_metadata(filename, mek);
api_request.file_data_hmac = context.hmac;

// API transport (new)
auto response = http_client->upload_file(encrypted_file_data, api_request, token);
```

### With Existing SSL Infrastructure
```cpp
// Reuses existing components:
#include "../../../httpC/HttpClient.h"      // SSL transport
#include "../../../sockets/SSLContext.h"    // SSL context

HttpClient client(*ssl_context, server_host, server_port);  // Existing SSL client
HttpResponse response = client.sendRequest(http_request);   // Existing method
```

## Usage Example

### Complete Upload/Share/Download Flow
```cpp
// 1. Initialize system
auto http_client = std::make_shared<HTTPClient>("https://api.server.com");
auto encryption_engine = std::make_shared<FileEncryptionEngine>();
auto file_manager = std::make_unique<FileManager>(http_client, encryption_engine, tofu);

// 2. Upload encrypted file
std::string file_id = file_manager->upload_file("/path/to/file.pdf", session_token);

// 3. Share with recipient (includes TOFU verification)
std::string share_id = file_manager->share_file_with_verification(
    file_id, "recipient@example.com", session_token);

// 4. Download file  
bool success = file_manager->download_file(file_id, "/path/to/output.pdf", session_token);
```

## Security Features Preserved

- ✅ **Server-side encryption agnostic** - Server never sees plaintext data or DEKs
- ✅ **AES-256-GCM authenticated encryption** - Crypto integrity maintained  
- ✅ **RSA-OAEP envelope encryption** - Secure DEK sharing
- ✅ **HMAC integrity verification** - Tamper detection
- ✅ **SSL/TLS transport security** - Network encryption
- ✅ **Session token authentication** - Access control

## Build Dependencies

Updated `CMakeLists.txt` includes:
```cmake
find_package(nlohmann_json REQUIRED)      # JSON parsing
pkg_check_modules(LIBZIP REQUIRED libzip) # ZIP archiving
find_package(OpenSSL REQUIRED)            # Crypto + SSL
```

## Testing

Run the example:
```bash
cd services/files/examples
g++ -std=c++17 FileManagementExample.cpp -o demo \
    -lFileManagement -lssl -lcrypto -lzip -lz
./demo
```

## Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| FileEncryptionEngine | ✅ Complete | Production-ready crypto |
| CompressionEngine | ✅ Complete | ZIP/zlib integration |
| DataConverter | ✅ Complete | Base64, JSON, multipart |
| HTTPClient | ✅ Complete | Full REST API coverage |
| FileManager | 🚧 Stubbed | High-level interface (TODOs) |
| SSL Infrastructure | ✅ Complete | Existing httpC/SSLContext |

## Next Steps

1. **Complete FileManager.cpp implementation** - Replace TODO stubs with actual logic
2. **Authentication integration** - Connect with Person 3's auth system
3. **TOFU integration** - Connect with Person 1's verification system  
4. **Error handling refinement** - More specific error conditions
5. **Performance optimization** - Streaming for large files

## Work Estimate

**Remaining effort**: ~2-3 days
- Day 1: Complete FileManager.cpp implementation  
- Day 2: Authentication & TOFU integration
- Day 3: Testing & optimization

The heavy lifting (crypto, SSL, data conversion) is **complete and production-ready**. 