#!/bin/bash

echo "Building Secure File Transfer Protocol..."

# Create clean build directory
echo "Cleaning build directory..."
rm -rf build
mkdir -p build

# Compile all Java files
echo "Compiling Java files..."
javac -d build src/common/*.java src/client/*.java src/server/*.java

if [ $? -eq 0 ]; then
    echo "Build successful! Files compiled to build directory."
    echo "To run the server: java -cp build server.Server"
    echo "To run the client: java -cp build client.ClientUI"
else
    echo "Build failed. See error messages above."
    exit 1
fi
