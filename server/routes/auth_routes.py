import logging
import os
import base64
import pyotp
import qrcode
import secrets
import hashlib
import hmac
import datetime
from io import BytesIO
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from server.database import Session, User
from server.routes.log_routes import log_audit
from security.srp_utils import N, g, k, H
from server.sanitization import validate_password_policy
from security.log_injections import *

# Load Environment Variables
load_dotenv()
key_str = os.getenv("SERVER_MASTER_KEY")
ca_pass_str = os.getenv("CA_KEY_PASSWORD")

# Password policy (minimum length)
try:
    MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", "12"))
except ValueError:
    MIN_PASSWORD_LENGTH = 12

if not key_str:
    raise ValueError("SERVER_MASTER_KEY not found in .env file!")

cipher = Fernet(key_str.encode())

router = APIRouter()

srp_sessions = {}

CA_CERT_PATH = "pki/certs/intermediate_ca.pem"
CA_KEY_PATH = "pki/certs/intermediate_ca_key.pem"

# --- HELPER FUNCTIONS ---

def encrypt_server_data(data: str) -> str:
    """Encrypts system data (like usernames) using the Server Master Key"""
    return cipher.encrypt(data.encode()).decode()

def decrypt_server_data(token: str) -> str:
    """Decrypts system data"""
    try:
        return cipher.decrypt(token.encode()).decode()
    except:
        return "Unknown"

def hash_username(username: str) -> str:
    """Creates a deterministic hash for DB indexing"""
    return hashlib.sha256(username.encode()).hexdigest()

def get_user_by_token(sess, raw_token_str):
    """
    Hashes the raw token provided by the client and looks up the user 
    by matching the hash stored in the database.
    """
    if not raw_token_str: return None
    input_hash = hashlib.sha256(raw_token_str.encode()).hexdigest()
    return sess.query(User).filter(User.token == input_hash).first()

def sign_user_csr(csr_pem: str, username: str) -> str:
    """Validates and signs a user's CSR using the Intermediate CA"""
    
    # 1. Load CA Certificate
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    # 2. Load Encrypted Private Key
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(), 
            password=ca_pass_str.encode() if ca_pass_str else None, 
            backend=default_backend()
        )

    # 3. Load User CSR
    csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())

    # 4. Verify Signature & Common Name
    if not csr.is_signature_valid:
        raise HTTPException(400, "Invalid CSR signature")

    try:
        csr_cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        raise HTTPException(400, "CSR missing Common Name (CN)")
        
    if csr_cn != username:
        raise HTTPException(403, f"CSR CN '{csr_cn}' does not match user '{username}'")

    # 5. Build & Sign Certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    certificate = builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend()
    )

    return certificate.public_bytes(serialization.Encoding.PEM).decode()

def generate_fake_salt(username: str) -> str:
    """
    Generates a deterministic 32-char hex string (16 bytes) based on the username.
    This ensures that querying a non-existent user always returns the SAME salt.
    """
    h = hmac.new(key_str.encode(), username.encode(), hashlib.sha256)
    return h.hexdigest()[:32]


# --- PYDANTIC MODELS ---
class RegisterRequest(BaseModel):
    username: str
    role: str
    salt: str       
    verifier: str   
    password_length: int
    # password: str   
    pub_key: Optional[str] = None  
    csr: Optional[str] = None
    encrypted_priv_key: str 
    encrypted_dob: Optional[str] = None       
    organization: Optional[str] = None
    
class SRPLoginInit(BaseModel):
    username: str
    A: str
    
class SRPLoginVerify(BaseModel):
    username: str
    M1: str         
    totp_code: Optional[str] = None

class AppointRequest(BaseModel):
    token: str
    doctor_username: str

class GetPubRequest(BaseModel):
    token: str
    username: str

class MeRequest(BaseModel):
    token: str

class QRRequest(BaseModel):
    token: str
    
class ChangeCredentialsRequest(BaseModel):
    token: str
    new_salt: str      
    new_verifier: str  
    password_length: int
    encrypted_priv_key: str     
    totp_code: str     
    
class SignCSRRequest(BaseModel):
    token: str
    csr_pem: str
    
class UsernameReq(BaseModel):
    username: str


# --- ROUTES ---

@router.post("/register")
def register(req: RegisterRequest, request: Request):
    """Registers a new user (patient or doctor)"""

    if req.role not in ("patient", "doctor"):
        raise HTTPException(400, "Invalid role")

    if req.password_length < MIN_PASSWORD_LENGTH:
        raise HTTPException(400, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long")
    
    org_enc = None
    
    if req.organization:
        org_enc = encrypt_server_data(req.organization)

    # Injection detection for logs
    detect_and_log_injection(req.username, "username", request)
    # detect_and_log_injection(req.password, "password", request)
    if req.organization: detect_and_log_injection(req.organization, "organization", request)
    if req.role: detect_and_log_injection(req.role, "role", request)

    # Validation
    if req.role == "patient" and not req.encrypted_dob:
        raise HTTPException(400, "Patients must provide a Date of Birth")
    if req.role == "doctor" and not req.organization:
        raise HTTPException(400, "Doctors must provide a Medical Organization")
        
    sess = Session()
    
    #  Check existence using HASH (User.username does not exist)
    u_hash = hash_username(req.username)
    
    if sess.query(User).filter(User.username_hash == u_hash).first():
        sess.close()
        log_audit(
            "REGISTER",
            user=req.username, # Plaintext OK here (Input)
            role=req.role,
            ip=request.client.host,
            result="Failed - username taken",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.INFO,
        )
        raise HTTPException(400, "Username taken")

    # --- PKI LOGIC: Handle CSR or Public Key ---
    pub_key_bytes = None
    certificate_pem = None

    if req.csr:
        try:
            # A. Load the CSR
            csr_obj = x509.load_pem_x509_csr(req.csr.encode(), default_backend())
            
            # B. Verify CSR Signature
            if not csr_obj.is_signature_valid:
                log_audit(
                    "REGISTER",
                    user=req.username,
                    role=req.role,
                    ip=request.client.host,
                    result="Failed - Invalid CSR signature",
                    user_agent=request.headers.get("user-agent"),
                    method=request.method,
                    path=request.url.path,
                    level=logging.WARNING,
                )
                raise HTTPException(400, "Invalid CSR signature")

            # C. Extract Public Key
            pub_key_obj = csr_obj.public_key()
            pub_key_bytes = pub_key_obj.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # D. Sign the CSR
            certificate_pem = sign_user_csr(req.csr, req.username)

        except Exception as e:
            print(f"CSR Processing Error: {e}")
            log_audit(
                "REGISTER",
                user=req.username,
                role=req.role,
                ip=request.client.host,
                result="Failed - Invalid CSR format or signature",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(400, "Invalid CSR format or signature")

    elif req.pub_key:
        # Fallback (TOFU)
        pub_key_bytes = base64.b64decode(req.pub_key)
    else:
        log_audit(
            "REGISTER",
            user=req.username,
            role=req.role,
            ip=request.client.host,
            result="Failed - No CSR or Public Key provided",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.WARNING,
        )
        raise HTTPException(400, "Must provide either CSR or Public Key")


    # 1. Generate Raw Secret for MFA
    raw_secret = pyotp.random_base32()
    
    # 2. Encrypt Secret before storage
    encrypted_secret = cipher.encrypt(raw_secret.encode()).decode()
    
    #  Encrypt Username for storage
    u_enc = encrypt_server_data(req.username)
    
    # Store User
    user = User(
        username_hash=u_hash,       # Blind Index
        encrypted_username=u_enc,   # Encrypted Data
        role=req.role,
        srp_salt=req.salt,
        srp_verifier=req.verifier,
        pub_key=pub_key_bytes,
        encrypted_priv_key=req.encrypted_priv_key, 
        mfa_secret=encrypted_secret,
        appointed_doctors=[] if req.role == "patient" else None,
        dob=req.encrypted_dob,
        organization=org_enc
    )
    sess.add(user)
    sess.commit()
    
    result_msg = "SUCCESS, user created"
    if certificate_pem:
        result_msg += " (Certificate Issued)"
    elif req.pub_key:
        result_msg += " (Public Key Uploaded)"
    
    log_audit(
        "REGISTER",
        user=req.username,
        role=user.role,
        ip=request.client.host,
        result=result_msg,
        user_agent=request.headers.get("user-agent"),
        method=request.method,
        path=request.url.path,
        level=logging.INFO,
    )
    sess.close()
    
    return {
        "status": "ok", 
        "mfa_secret": raw_secret,
        "certificate": certificate_pem 
    }
    
@router.post("/get_salt")
def get_salt_only(req: UsernameReq):
    sess = Session()
    try:
        #  Lookup by Hash
        u_hash = hash_username(req.username)
        user = sess.query(User).filter(User.username_hash == u_hash).first()
        if not user:
            # Deterministic Fake Salt
            fake_salt = generate_fake_salt(req.username)
            return {"salt": fake_salt}
        
        return {"salt": user.srp_salt}
    finally:
        sess.close()

@router.post("/login/init")
def login_init(req: SRPLoginInit, request: Request):
    """Step 1: Receive A, Return Salt + B"""
    detect_and_log_injection_login_input(req.username, "username", request)
    
    sess = Session()
    #  Lookup by Hash
    u_hash = hash_username(req.username)
    user = sess.query(User).filter(User.username_hash == u_hash).first()
    sess.close()

    if not user:
        log_audit(
            "LOGIN",
            user=req.username,
            role="unknown",
            ip=request.client.host,
            result="Failed - non-existent user",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.WARNING,
        )
        fake_salt = generate_fake_salt(req.username)
        fake_B = secrets.token_hex(256) 
        return {"salt": fake_salt, "B": fake_B}

    # Real User Logic
    b = secrets.randbelow(N)
    v = int(user.srp_verifier, 16)
    
    # B = kv + g^b (mod N)
    B = (k * v + pow(g, b, N)) % N
    
    srp_sessions[req.username] = {
        "b": b, "B": B, "v": v, "salt": user.srp_salt, "A": int(req.A, 16)
    }
    
    return {"salt": user.srp_salt, "B": hex(B)[2:]}

@router.post("/login/verify")
def login_verify(req: SRPLoginVerify, request: Request):
    """Step 2: Verify M1, Return M2 + Token"""
    detect_and_log_injection_login_input(req.username, "username", request)
    detect_and_log_injection(req.totp_code, "totp_code", request)

    session_data = srp_sessions.pop(req.username, None)
    if not session_data:
        log_audit(
            "LOGIN",
            user=req.username,
            role="unknown",
            ip=request.client.host,
            result="Failed - No SRP Session",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.WARNING,
        )
        raise HTTPException(400, "Session expired or invalid")

    sess = Session()
    try:
        #  Lookup by Hash
        u_hash = hash_username(req.username)
        user = sess.query(User).filter(User.username_hash == u_hash).first()
        if not user:
            log_audit(
                "LOGIN",
                user=req.username,
                role="unknown",
                ip=request.client.host,
                result="Failed - non-existent user",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(400, "Session expired or invalid")
        
        # --- 1. CHECK MFA ---
        if user.mfa_secret:
            try:
                real_secret = cipher.decrypt(user.mfa_secret.encode()).decode()
                
                if not req.totp_code:
                    log_audit(
                        "LOGIN",
                        user=req.username,
                        role=user.role,
                        ip=request.client.host,
                        result="Failed - Missing TOTP code",
                        user_agent=request.headers.get("user-agent"),
                        method=request.method,
                        path=request.url.path,
                        level=logging.WARNING,
                    )
                    raise ValueError("Missing TOTP code")
                      
                if not pyotp.TOTP(real_secret).verify(req.totp_code):
                    log_audit(
                        "LOGIN",
                        user=req.username,
                        role=user.role,
                        ip=request.client.host,
                        result="Failed - Invalid TOTP code",
                        user_agent=request.headers.get("user-agent"),
                        method=request.method,
                        path=request.url.path,
                        level=logging.WARNING,
                    )
                    raise HTTPException(401, "Invalid TOTP code")
                    
            except HTTPException:
                raise 
            except Exception as e:
                print(f"CRITICAL MFA ERROR: {str(e)}") 
                log_audit(
                    "LOGIN",
                    user=req.username,
                    role=user.role,
                    ip=request.client.host,
                    result="Failed - Server Security Error during MFA",
                    user_agent=request.headers.get("user-agent"),
                    method=request.method,
                    path=request.url.path,
                    level=logging.CRITICAL,
                )
                raise HTTPException(500, f"Server Security Error: {str(e)}")

        # --- 2. SRP Math ---
        A, B, b, v = session_data['A'], session_data['B'], session_data['b'], session_data['v']
        
        if A % N == 0: raise HTTPException(401, "Invalid A")

        u = H(A, B)
        S = pow((A * pow(v, u, N)) % N, b, N)
        K = H(S)

        # --- 3. Check M1 ---
        expected_M1_int = H(A, B, K)
        
        try:
            client_M1_int = int(req.M1, 16)
        except ValueError:
            raise HTTPException(400, "Malformed M1 hex string")

        if client_M1_int != expected_M1_int:
            log_audit(
                "LOGIN",
                user=req.username,
                role=user.role,
                ip=request.client.host,
                result="Failed - Proof Mismatch",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.DEBUG,
            )
            raise HTTPException(401, "Invalid Password Proof")

        # --- 4. Calculate M2 ---
        M2_int = H(A, expected_M1_int, K)
        
        # Ensure M2 hex string is padded to even length
        m2_hex = hex(M2_int)[2:]
        if len(m2_hex) % 2 == 1:
            m2_hex = '0' + m2_hex
        
        raw_token = secrets.token_hex(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        user.token = token_hash
        sess.commit()
        
        log_audit(
            "LOGIN",
            user=req.username,
            role=user.role,
            ip=request.client.host,
            result="SUCCESS",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.INFO,
        )
        return {"token": raw_token, "M2": hex(M2_int)[2:]}

    finally:
        sess.close()


@router.post("/appoint")
def appoint(req: AppointRequest, request: Request):
    detect_and_log_injection_appoint_input(req.doctor_username, "doctor_username", request)
    detect_and_log_injection(req.token, "token", request)

    sess = Session()
    try:
        patient = get_user_by_token(sess, req.token)
        if not patient:
            log_audit(
                "APPOINT",
                user="unknown",
                role="unknown",
                ip=request.client.host,
                doctor=req.doctor_username,
                result="Failed - invalid token",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(401, "Unauthorized: invalid or expired token")

        # Decrypt Patient Name for Logs (User.username doesn't exist)
        pat_name_log = decrypt_server_data(patient.encrypted_username)

        if patient.role != "patient":
            log_audit(
                "APPOINT",
                user=pat_name_log,
                role=patient.role,
                ip=request.client.host,
                doctor=req.doctor_username,
                result="Failed - non-patient tried to appoint",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(403, "Only patients can appoint doctors")

        # Check Doctor using HASH
        doc_hash_input = hash_username(req.doctor_username)
        doctor = sess.query(User).filter(User.username_hash == doc_hash_input, User.role == "doctor").first()
        
        if not doctor:
            log_audit(
                "APPOINT",
                user=pat_name_log,
                role=patient.role,
                ip=request.client.host,
                doctor=req.doctor_username,
                result="Failed - doctor not found",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(404, "Doctor not found")
        
        # Use stored hash
        doctor_hash = doctor.username_hash
        
        current_list = list(patient.appointed_doctors) if patient.appointed_doctors else []
        
        if doctor_hash not in current_list:
            current_list.append(doctor_hash)
            patient.appointed_doctors = current_list 
            sess.commit()

        log_audit(
            "APPOINT",
            user=pat_name_log,
            role=patient.role,
            ip=request.client.host,
            doctor=req.doctor_username,
            result="SUCCESS, doctor appointed",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.INFO,
        )
        return {"status": "ok"}
    finally:
        sess.close()

@router.post("/remove_doctor")
def remove_doctor(req: AppointRequest, request: Request):
    sess = Session()
    try:
        patient = get_user_by_token(sess, req.token)
        if not patient or patient.role != "patient":
            log_audit(
                "REMOVE_DOC",
                user="unknown",
                role="unknown",
                ip=request.client.host,
                doctor=req.doctor_username,
                result="Unauthorized",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(401, "Unauthorized")
        
        pat_name_log = decrypt_server_data(patient.encrypted_username)

        # Hash input to remove
        doctor_hash = hash_username(req.doctor_username)

        current_list = list(patient.appointed_doctors) if patient.appointed_doctors else []
        
        if doctor_hash in current_list:
            current_list.remove(doctor_hash)
            patient.appointed_doctors = current_list
            sess.commit()
            log_audit(
                "REMOVE_DOC", 
                user=pat_name_log,
                role=patient.role, 
                doctor=req.doctor_username, 
                ip=request.client.host, 
                result="SUCCESS", 
                user_agent=request.headers.get("user-agent"), 
                method=request.method, 
                path=request.url.path, 
                level=logging.INFO,
            )
            return {"status": "ok", "message": "Doctor removed"}
        else:
            log_audit(
                "REMOVE_DOC", 
                user=pat_name_log,
                role=patient.role,
                doctor=req.doctor_username, 
                ip=request.client.host, 
                result="Failed - Doctor not appointed", 
                user_agent=request.headers.get("user-agent"), 
                method=request.method, 
                path=request.url.path, 
                level=logging.WARNING,
            )
            raise HTTPException(404, "Doctor was not appointed")
    finally:
        sess.close()

@router.post("/get_pubkey")
def get_pubkey(req: GetPubRequest, request: Request):
    detect_and_log_injection(req.username, "username", request)
    sess = Session()
    
    requester = get_user_by_token(sess, req.token)
    if not requester: 
        log_audit(
            "GET_PUBKEY",
            user="unknown",
            role="unknown",
            ip=request.client.host,
            result="Failed - unauthorized",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.WARNING,
        )
        sess.close()
        raise HTTPException(401, "Unauthorized")
    
    req_name_log = decrypt_server_data(requester.encrypted_username)

    # 1. Assume input is Plaintext -> Hash it
    target_hash = hash_username(req.username)
    target = sess.query(User).filter(User.username_hash == target_hash).first()
    
    # 2. If not found, assume input IS the Hash
    if not target:
        target = sess.query(User).filter(User.username_hash == req.username).first()
        
    if not target:
        log_audit(
            "GET_PUBKEY",
            user=req_name_log,
            role=requester.role,
            ip=request.client.host,
            result="Failed - user not found",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.WARNING,
        )
        sess.close()
        raise HTTPException(404, "User not found")

    log_audit(
        "GET_PUBKEY",
        user=req_name_log,
        role=requester.role,
        ip=request.client.host,
        result="SUCCESS, public key retrieved",
        user_agent=request.headers.get("user-agent"),
        method=request.method,
        path=request.url.path,
        level=logging.INFO,
    )
    sess.close()
    return {"pub_key": base64.b64encode(target.pub_key).decode()}

@router.post("/me")
def me(req: MeRequest, request: Request):
    sess = Session()
    try:
        user = get_user_by_token(sess, req.token)
        if not user:
            log_audit(
                "ME",
                user="unknown",
                role="unknown",
                ip=request.client.host,
                req_token=req.token,
                result="FAILED - unauthorized",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(401, "Unauthorized")
        
        # Decrypt name for display
        real_username = decrypt_server_data(user.encrypted_username)
        
        real_org = None
        if user.role == "doctor" and user.organization:
            try:
                real_org = decrypt_server_data(user.organization)
            except Exception:
                real_org = "Error Decrypting Org"
        
        return {
            "username": real_username, 
            "role": user.role, 
            "encrypted_priv_key": user.encrypted_priv_key,
            "organization": real_org
        }
    finally:
        sess.close()

@router.post("/qr")
def get_qr(req: QRRequest, request: Request):
    sess = Session()
    try:
        user = get_user_by_token(sess, req.token)
        if not user or not user.mfa_secret:
            log_audit(
                "QR TOKEN",
                user="unknown", 
                role="unknown",
                ip=request.client.host,
                result="Failed - MFA not enabled or unauthorized",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(400, "MFA not enabled")

        # Decrypt Name for TOTP Issuer
        real_username = decrypt_server_data(user.encrypted_username)

        try:
            real_secret = cipher.decrypt(user.mfa_secret.encode()).decode()
            totp_uri = pyotp.totp.TOTP(real_secret).provisioning_uri(
                name=real_username,
                issuer_name="SecureMedicalRecords"
            )
        except Exception as e:
            print(f"QR Decryption Error: {e}")
            log_audit(
                "QR TOKEN",
                user=real_username, 
                role=user.role,
                ip=request.client.host,
                result="Failed - Error decrypting MFA secret",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.ERROR,
            )
            raise HTTPException(500, "Error decrypting MFA secret")

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        log_audit(
            "QR TOKEN",
            user=real_username,
            role=user.role,
            ip=request.client.host,
            result="SUCCESS, QR code generated",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.INFO,
        )
        return {"qr_code": f"data:image/png;base64,{img_str}"}
    finally:
        sess.close()
        
        
@router.post("/change_credentials")
def change_credentials(req: ChangeCredentialsRequest, request: Request):
    detect_and_log_injection(req.totp_code, "totp_code", request)
    # detect_and_log_injection(req.password, "password", request)
    
    sess = Session()
    try:
        user = get_user_by_token(sess, req.token)
        if not user:
            log_audit(
                "CHANGE_CREDS",
                user="unknown",
                role="unknown",
                ip=request.client.host,
                result="Unauthorized",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(401, "Unauthorized")
        
        # Get Name for Log
        user_name_log = decrypt_server_data(user.encrypted_username)

        if req.password_length < MIN_PASSWORD_LENGTH:
            log_audit(
                "CHANGE_CREDS",
                user=user_name_log,
                role=user.role,
                ip=request.client.host,
                result="Failed - Password too short",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(400, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long")

        # validate_password_policy(req.password)

        if not user.mfa_secret:
            log_audit(
                "CHANGE_CREDS",
                user=user_name_log,
                role=user.role,
                ip=request.client.host,
                result="Failed - MFA not enabled",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(400, "MFA not enabled")
        
        try:
            real_secret = cipher.decrypt(user.mfa_secret.encode()).decode()
        except Exception as e:
            print(f"MFA Decrypt Error: {e}")
            log_audit(
                "CHANGE_CREDS",
                user=user_name_log,
                role=user.role,
                ip=request.client.host,
                result="Failed - Server Error decrypting MFA secret",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.ERROR,
            )
            raise HTTPException(500, "Server Error: Could not decrypt MFA secret")

        if not pyotp.TOTP(real_secret).verify(req.totp_code):
            log_audit(
                "CHANGE_CREDS",
                user=user_name_log,
                role=user.role,
                ip=request.client.host,
                result="Failed - Invalid TOTP",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(401, "Invalid TOTP code")

        user.srp_salt = req.new_salt
        user.srp_verifier = req.new_verifier
        user.encrypted_priv_key = req.encrypted_priv_key
        sess.commit()
        
        log_audit(
            "CHANGE_CREDS",
            user=user_name_log,
            role=user.role,
            ip=request.client.host,
            result="Success",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.INFO,
        )
        return {"status": "ok", "message": "Credentials updated successfully"}
    
    finally:
        sess.close()
        
        
@router.post("/sign_csr")
def sign_csr_endpoint(req: SignCSRRequest, request: Request):
    sess = Session()
    try:
        user = get_user_by_token(sess, req.token)
        if not user:
            log_audit(
                "CSR_SIGN",
                user="unknown",
                role="unknown",
                ip=request.client.host,
                result="Unauthorized",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(401, "Unauthorized")

        # Decrypt name for Signing and Logs
        real_username = decrypt_server_data(user.encrypted_username)

        try:
            cert_pem = sign_user_csr(req.csr_pem, real_username)
        except Exception as e:
            log_audit(
                "CSR_SIGN",
                user=real_username,
                role=user.role,
                ip=request.client.host,
                result=f"Failed - {str(e)}",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.ERROR,
            )
            raise HTTPException(400, f"Signing failed: {str(e)}")

        log_audit(
            "CSR_SIGN",
            user=real_username,
            role=user.role,
            ip=request.client.host,
            result="SUCCESS, Certificate Issued",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.INFO,
        )
        return {"status": "ok", "certificate": cert_pem}
    finally:
        sess.close()