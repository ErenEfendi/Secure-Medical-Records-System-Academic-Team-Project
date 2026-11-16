#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "========================================"
echo "   Secure Medical Records System Setup"
echo "========================================"

# 1. Install Python Dependencies
echo "[1/3] Installing Python Dependencies..."
pip3 install -r requirements.txt

# 2. Generate PKI Certificates
# We use 'python3 -m' to run the module, ensuring imports work correctly
echo "[2/3] Generating PKI Certificates..."
python3 -m pki.create_ca

# 3. Start the Server
echo "[3/3] Starting Secure Server..."
echo "----------------------------------------"
echo "Server is running at: https://localhost:8000"
echo "Press Ctrl+C to stop."
echo "----------------------------------------"

# Run Uvicorn with SSL settings
uvicorn server.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --ssl-keyfile pki/certs/server_key.pem \
    --ssl-certfile pki/certs/server_chain.pem \
    --log-level info