#!/bin/bash

# Create build directory if it doesn't exist
mkdir -p build

# Generate build files with CMake
cd build && cmake ..

# Build the project
cmake --build .

echo -e "\nBuild completed successfully!"
echo "Run the server with: ./run_server.sh"
echo "Run the client with: ./run_client.sh"
echo "Run the test with:   ./build/secure_communication_test" 