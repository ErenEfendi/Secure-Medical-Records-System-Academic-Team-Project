# Secure Medical Records System

An academic client/server project for storing and accessing medical records with a focus on privacy, authentication, and access control.

## Project Overview

The system is designed so that medical records are encrypted on the client before they are sent to the server. The server stores encrypted records and handles the requests needed to access them. Doctors and patients have different permissions through role-based access control (RBAC).

The project uses Secure Remote Password (SRP) for authentication and a public key infrastructure (PKI) for the server's HTTPS certificate.

## Security Features

| Feature | Purpose |
| --- | --- |
| Client-side encryption | Encrypt medical records before uploading them and decrypt them on the client. |
| Secure Remote Password (SRP) | Authenticate users without sending their plaintext password to the server. |
| Role-based access control (RBAC) | Apply different access permissions to doctors and patients. |
| HTTPS | Protect communication with the server using TLS. |
| PKI certificate generation | Generate certificates required to run the HTTPS server. |
| Integrity and signing keys | Support the application's configured HMAC and log-signing operations. |

The server is intended to store medical records in encrypted form. The precise metadata visible to the server depends on the implementation and deployment configuration.

## Prerequisites

- Windows 10/11 (x64) or Ubuntu 22.04 (x64)
- Python 3.10 or newer
- OpenSSL, if required for certificate generation in your environment

## Configuration

Create a local `.env` file using `.env.example` as a template. Set the values required by your deployment before starting the server. Do not commit `.env`, passwords, generated private keys, or real medical records.

The configuration includes:

| Variable | Purpose |
| --- | --- |
| `AUDIT_HMAC_KEY` | Key for audit-related HMAC operations |
| `CLIENT_HMAC_KEY` | Key for client-related HMAC operations |
| `SERVER_MASTER_KEY` | Server master key |
| `CA_KEY_PASSWORD` | Password for the certificate authority's private key |
| `MIN_PASSWORD_LENGTH` | Minimum accepted password length |
| `LOG_ENC_KEY` | Key for log encryption |
| `LOG_SIGN_KEY` | Private key used for log signing |

Use values in the format expected by the application. In particular, `LOG_SIGN_KEY` must contain a valid private key in the format the code supports; a shortened PEM header is not sufficient.

## Running the Project

Run the following commands from the repository root.

### Automatic setup on Ubuntu

```bash
chmod +x run.sh
./run.sh
```

### Manual setup

1. Install the Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Generate the PKI certificates:

   ```bash
   python pki/create_ca.py
   ```

   On systems where Python is invoked as `python3`, use:

   ```bash
   python3 pki/create_ca.py
   ```

   Confirm that certificate generation created the required files under `pki/certs/`.

3. Start the HTTPS server:

   ```bash
   uvicorn server.main:app --host 0.0.0.0 --port 8000 \
     --ssl-keyfile pki/certs/server_key.pem \
     --ssl-certfile pki/certs/server_chain.pem \
     --log-level info
   ```

   In PowerShell, run the same command on one line:

   ```powershell
   uvicorn server.main:app --host 0.0.0.0 --port 8000 --ssl-keyfile pki/certs/server_key.pem --ssl-certfile pki/certs/server_chain.pem --log-level info
   ```

4. To start the monitor, open a second terminal in the repository root and run:

   ```bash
   python -m server.monitor
   ```

## Expected Behavior

Once configured and started, the server listens over HTTPS on port `8000`. Clients can authenticate through the project's SRP flow and access medical records according to their assigned role. Medical record encryption and decryption are performed by the client.

## Project Scope

This repository is an academic implementation intended for learning and security research. Its security properties depend on correct configuration, key protection, certificate handling, and deployment.