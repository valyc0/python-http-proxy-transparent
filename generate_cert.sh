#!/bin/bash
# generate_cert.sh - Script to generate a self-signed certificate for HTTPS interception

CERT_DIR="./certs"
CERT_FILE="$CERT_DIR/proxy.crt"
KEY_FILE="$CERT_DIR/proxy.key"

# Create certificate directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Check if certificate files already exist
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "Certificate files already exist:"
    echo "  Certificate: $CERT_FILE"
    echo "  Private key: $KEY_FILE"
    echo "To generate new files, delete these files and run this script again."
    exit 0
fi

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
    echo "Error: OpenSSL is not installed. Please install it first."
    exit 1
fi

echo "Generating self-signed certificate for HTTPS interception..."

# Generate a private key
openssl genrsa -out "$KEY_FILE" 2048

# Generate a self-signed certificate
openssl req -new -x509 -key "$KEY_FILE" -out "$CERT_FILE" -days 3650 -subj "/CN=HTTP Proxy Logger CA"

# Check if generation was successful
if [ $? -eq 0 ]; then
    echo "Certificate generated successfully!"
    echo "  Certificate: $CERT_FILE"
    echo "  Private key: $KEY_FILE"
    echo ""
    echo "IMPORTANT: For HTTPS interception to work, you need to add this certificate"
    echo "           to your system or browser's trusted certificate authorities."
    echo ""
    echo "On most systems, you can import the certificate with:"
    echo "  Firefox: Settings -> Privacy & Security -> View Certificates -> Import"
    echo "  Chrome: Settings -> Privacy and security -> Security -> Manage certificates -> Import"
    echo "  macOS: Import the certificate into Keychain and trust it"
    echo "  Linux: It varies by distribution"
    echo ""
    echo "Alternatively, you can ignore certificate warnings in your client or use the -k flag with curl."
else
    echo "Error: Failed to generate certificate."
    exit 1
fi
