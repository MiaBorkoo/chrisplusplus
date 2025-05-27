# chrisplusplus
ISE Block 8 EPIC Project

## Build Requirements
- CMake 3.19 or higher
- Qt 6.5.0 or higher
- OpenSSL
- Ninja build system

## Building the Project

### Qt Setup
This project requires Qt 6.5.0 or higher. You can:
1. Install Qt from the [official Qt website](https://www.qt.io/download-qt-installer)
2. Or use your system's package manager if it provides a compatible version

### Local Build Configuration
The project uses CMake presets for build configuration. To set up your local Qt path:

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

2. Replace `/path/to/your/qt/installation` with your Qt installation path
   - For example: `/opt/Qt/6.5.0/gcc_64` on Linux
   - Or `C:/Qt/6.5.0/msvc2019_64` on Windows

3. Build using your local preset:
```bash
cmake --preset local-qt
cmake --build build
```

Note: `CMakeUserPresets.json` is gitignored and won't be committed, allowing each developer to maintain their own local settings.
