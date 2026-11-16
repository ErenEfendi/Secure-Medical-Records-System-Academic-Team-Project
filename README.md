#  Secure Medical Records System (Academic Project)

##  Project Overview

This project implements a **secure client/server system** for managing **medical records** with strong privacy guarantees.

### Security Features
- **End-to-End Encryption (E2EE)** for all medical data  
- **Zero-Knowledge Authentication** using **Secure Remote Password (SRP)**  
- **Role-Based Access Control (RBAC)** for doctors and patients  

The server acts as an **untrusted storage provider**:
- No plaintext passwords
- No plaintext medical records
- No sensitive metadata (filenames, timestamps)

All cryptographic operations occur **client-side only**.

---

##  Prerequisites
- **OS:** Windows 10/11 (x64) or Ubuntu 22.04 (x64)
- **Python:** 3.10 or higher
- **OpenSSL:** Optional for PKI certificate generation

---

##  Starting the Server (From Root Folder)

- for automatic installation
chmod +x run.sh
./run.sh

- For manual

1) Install dependencies
pip install -r requirements.txt

2) Generate PKI certificates
python pki/create_ca.py
(or)
python3 pki/create_ca.py

Ensure the folder pki/certs/ is created.

3) Start the secure server
uvicorn server.main:app --host 0.0.0.0 --port 8000 \
  --ssl-keyfile pki/certs/server_key.pem \
  --ssl-certfile pki/certs/server_chain.pem \
  --log-level info

4) to start monitor
python -m server.monitor

Result
- Server runs securely over HTTPS on port 8000
- Authentication uses Zero-Knowledge SRP
- Medical records remain encrypted even if the server is compromised

Notes
- All encryption/decryption is performed on the client
- Server never accesses sensitive data
- Intended for academic and security research purposes
