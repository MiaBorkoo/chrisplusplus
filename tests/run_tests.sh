#!/bin/bash

# Script to build and run engine tests

set -e  # Exit on any error

echo "=== Building Engine Tests ==="

# Create build directory
mkdir -p build
cd build

# Configure with CMake
cmake ..

# Build the tests
make -j$(nproc)

echo "=== Running Engine Tests ==="

# Run the tests
./engine_tests

echo "=== Tests Complete ===" 