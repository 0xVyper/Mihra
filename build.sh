#!/bin/bash

# Build script for Mihra with three-layer encryption

echo "Building Mihra..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go first."
    exit 1
fi

# Generate RSA key pair if they don't exist
if [ ! -f "private_key.pem" ] || [ ! -f "public_key.pem" ]; then
    echo "Generating RSA key pair..."
    go run -mod=mod ./internals/main.go -generate-keys
    if [ $? -ne 0 ]; then
        echo "Error: Failed to generate RSA key pair."
        exit 1
    fi
    echo "RSA key pair generated successfully."
fi

echo "Building Mihra binary..."
go build -o mihra ./cmd/mihra/main.go
if [ $? -ne 0 ]; then
    echo "Error: Failed to build Mihra binary."
    exit 1
fi

echo "Mihra built successfully encryption."
echo "You can now run the binary with:"
echo "  - Server mode: ./mihra -mode c2-server -host 0.0.0.0 -port 8443 "
echo "  - Client mode: ./mihra -mode c2-client -host <target> -port 8443 "
echo "  - Secure shell: ./mihra -mode secure_shell -shell-host <target> -shell-port 8443 "