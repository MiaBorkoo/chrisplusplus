# ChrisPlusPlus - Secure File Management System

## Overview
ChrisPlusPlus is a robust, secure file management system built with Qt and C++. It provides end-to-end encryption, secure file sharing, and advanced security features including TOTP-based two-factor authentication.

## Key Features

### Security
- End-to-end encryption using AES-256-GCM
- Two-factor authentication (TOTP) support
- Trust on First Use (TOFU) implementation
- Secure key derivation and management
- HMAC-based file integrity verification
- SSL/TLS encrypted communication

### File Management
- Secure file upload and download
- File sharing with granular access control
- File compression support
- Audit logging
- File metadata management
- Paginated file listing

### User Interface
- Modern Qt-based GUI
- Intuitive file dashboard
- Shared files view
- Account management section
- Progress tracking for file operations
- Dark mode support

## Technical Stack

### Core Technologies
- C++17
- Qt 6.5.0+
- OpenSSL
- CMake 3.19+
- Ninja build system

### Security Components
- AES-256-GCM for file encryption
- RSA-OAEP for key exchange
- HMAC-SHA256 for integrity verification
- RFC-6238 compliant TOTP implementation
- Custom TOFU protocol for device trust

## Build Requirements

### Prerequisites
- CMake 3.19 or higher
- Qt 6.5.0 or higher
- OpenSSL
- Ninja build system
- C++17 compatible compiler

### Dependencies
- zlib (compression)
- libzip (archive handling)
- qrencode (QR code generation)
- nlohmann_json (JSON parsing)

## Building the Project

### Qt Setup
1. Install Qt 6.5.0 or higher:
   - Download from [Qt's official website](https://www.qt.io/download-qt-installer)
   - Or use your system's package manager

### Local Build Configuration

1. Create a `CMakeUserPresets.json` file in the project root:
```json
{
    "version": 4,
    "include": ["CMakePresets.json"],
    "configurePresets": [
        {
            "name": "local-qt",
            "inherits": "default",
            "displayName": "Local Qt Config",
            "description": "Using local Qt installation",
            "cacheVariables": {
                "CMAKE_PREFIX_PATH": "/path/to/your/qt/installation"
            }
        }
    ],
    "buildPresets": [
        {
            "name": "local-qt",
            "configurePreset": "local-qt"
        }
    ]
}
```

2. Replace `/path/to/your/qt/installation` with your Qt installation path:
   - Linux: `/opt/Qt/6.5.0/gcc_64`
   - Windows: `C:/Qt/6.5.0/msvc2019_64`

3. Build the project:
```bash
cmake --preset local-qt
cmake --build build
```

## Project Structure

### Core Components
- `/controllers` - MVC controllers for UI logic
- `/models` - Data models and business logic
- `/views` - Qt-based UI components
- `/services` - Core services (auth, file management)
- `/crypto` - Cryptographic operations
- `/network` - Network communication layer
- `/utils` - Utility functions and helpers

### Key Services
- `AuthService` - Authentication and user management
- `FileService` - File operations and sharing
- `TOFUService` - Device trust management
- `CompressionEngine` - File compression
- `FileEncryptionEngine` - Cryptographic operations

## Security Features

### Authentication
- Password-based authentication
- TOTP-based 2FA
- Session management
- Password change functionality

### File Security
- Client-side encryption
- Secure key exchange
- File integrity verification
- Access control lists
- Audit logging

### Device Trust
- TOFU-based device verification
- QR code verification
- Device certificate management
- Trust chain validation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

