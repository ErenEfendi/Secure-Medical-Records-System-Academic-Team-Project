# pki/create_ca.py
import os
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import AuthorityKeyIdentifier, SubjectKeyIdentifier, KeyUsage, SubjectAlternativeName
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# Load environment variables (for CA Password)
# Assuming .env is in the project root (one level up from pki/)
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

# Fetch the password
CA_PASSWORD_STR = os.getenv("CA_KEY_PASSWORD")
if not CA_PASSWORD_STR:
    print("WARNING: CA_KEY_PASSWORD not found in .env. Keys will be unencrypted!")
    CA_PASSWORD_BYTES = None
else:
    CA_PASSWORD_BYTES = CA_PASSWORD_STR.encode()

def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def build_cert(subject: str, issuer_key, issuer_name, pub_key, is_ca: bool = False, issuer_cert=None, is_server: bool = False):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(pub_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )

        builder = builder.add_extension(
            KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False,
                decipher_only=False, key_cert_sign=True, crl_sign=True
            ),
            critical=True
        )

    builder = builder.add_extension(SubjectKeyIdentifier.from_public_key(pub_key), critical=False)

    if issuer_cert:
        aki = AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            issuer_cert.extensions.get_extension_for_class(SubjectKeyIdentifier).value
        )
        builder = builder.add_extension(aki, critical=False)

    if is_server:
        # Subject Alternative Names
        builder = builder.add_extension(
            SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False
        )
        
        # Extended Key Usage for Server Auth
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )

        # Key Usage for Server Certs
        builder = builder.add_extension(
            KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,    
                crl_sign=False          
            ),
            critical=True
        )
        
        # Basic Constraints for Server Certs
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )


    return builder.sign(issuer_key, hashes.SHA256())

# Save certificate and key to files
def save_cert_and_key(name, cert, key, encrypt_key=False):
    os.makedirs("pki/certs", exist_ok=True)
    
    # Save Certificate (Public)
    with open(f"pki/certs/{name}.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Determine Encryption
    if encrypt_key and CA_PASSWORD_BYTES:
        encryption_algo = serialization.BestAvailableEncryption(CA_PASSWORD_BYTES)
        print(f"Saving {name} key ENCRYPTED.")
    else:
        encryption_algo = serialization.NoEncryption()
        print(f"Saving {name} key UNENCRYPTED.")

    # Save Private Key
    with open(f"pki/certs/{name}_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        ))

def main():
    root_key = generate_key()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    root_cert = build_cert("Root CA", root_key, root_name, root_key.public_key(), is_ca=True)
    # Encrypt Root CA Key
    save_cert_and_key("root_ca", root_cert, root_key, encrypt_key=True)

    inter_key = generate_key()
    inter_cert = build_cert("Intermediate CA", root_key, root_name, inter_key.public_key(), is_ca=True, issuer_cert=root_cert)
    # Encrypt Intermediate CA Key
    save_cert_and_key("intermediate_ca", inter_cert, inter_key, encrypt_key=True)

    server_key = generate_key()
    server_cert = build_cert("Server", inter_key, inter_cert.subject, server_key.public_key(), issuer_cert=inter_cert, is_server=True)
    # Keep Server Key Unencrypted (for auto-restart convenience)
    save_cert_and_key("server", server_cert, server_key, encrypt_key=False)

    with open("pki/certs/server_chain.pem", "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
        f.write(inter_cert.public_bytes(serialization.Encoding.PEM))

    print("PKI generated successfully.")

if __name__ == "__main__":
    main()