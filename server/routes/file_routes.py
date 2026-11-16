from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any, List
import hashlib
import logging
import base64
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from security.log_injections import detect_and_log_injection
from server.database import Session, User, MedicalRecord, PendingRequest
from server.routes.log_routes import log_audit
from typing import Optional

# --- Load Encryption for Server-Side Data (Usernames) ---
load_dotenv()
key_str = os.getenv("SERVER_MASTER_KEY")
if not key_str:
    raise RuntimeError("SERVER_MASTER_KEY not found in env")
cipher = Fernet(key_str.encode())

router = APIRouter()

# --- Helper Functions ---

def decrypt_server_data(token: str) -> str:
    """Decrypts system data (like usernames) using the Server Master Key"""
    try:
        return cipher.decrypt(token.encode()).decode()
    except:
        return "Unknown/Error"

def get_user_by_token(sess, raw_token_str):
    """
    Hashes the raw token provided by the client and looks up the user 
    by matching the hash stored in the database.
    """
    if not raw_token_str:
        return None
    
    # Hash the input token to match the stored hash in the DB
    input_hash = hashlib.sha256(raw_token_str.encode()).hexdigest()
    
    return sess.query(User).filter(User.token == input_hash).first()

def hash_username(username: str) -> str:
    """Creates a deterministic hash for DB indexing"""
    return hashlib.sha256(username.encode()).hexdigest()


# --- Pydantic Models for Requests ---

class TokenReq(BaseModel):
    token: str

class UploadReq(BaseModel):
    token: str
    encrypted_metadata: str  # Base64 encrypted JSON
    patient_username: str
    encrypted_blob: str
    public_metadata: Dict[str, Any] # Non-sensitive info only.
    wrapped_keys: Dict[str, Dict[str, str]]
    signature: str  # Base64 signature of (encrypted_metadata + encrypted_blob)

class DownloadReq(BaseModel):
    token: str
    record_id: int 

class ShareReq(BaseModel):
    token: str
    record_id: int 
    doctor_username: str
    wrapped_key: Dict[str, str]
    
class DeleteReq(BaseModel):
    token: str
    record_id: int
    
class UpdateReq(BaseModel):
    token: str
    record_id: int
    encrypted_blob: str
    encrypted_metadata: str
    signature: str
    wrapped_keys: Dict[str, Dict[str, str]]
    
class ListReq(BaseModel):
    token: str
    patient_username: Optional[str] = None
    
class AppointedForPatientReq(BaseModel):
    token: str
    patient_username: str


# --- Routes ---

@router.post("/appointed_doctors")
def appointed_doctors(req: TokenReq, request: Request):
    sess = Session()
    try:
        user = get_user_by_token(sess, req.token)
        if not user:
             log_audit("APPOINTED_DOCS", user="unknown", ip=request.client.host, result="FAILED - Invalid Token", level=logging.WARNING)
             raise HTTPException(401, "Invalid token")
        
        # Log decrypted name
        user_name_log = decrypt_server_data(user.encrypted_username)

        if user.role != "patient":
            log_audit("APPOINTED_DOCS", user=user_name_log, ip=request.client.host, result="FAILED - Only patients have appointed doctors", level=logging.WARNING)
            raise HTTPException(403, "Only patients have appointed doctors")
        
        hashes = user.appointed_doctors or []
        if not hashes:
            return []

        # Fetch all doctors and match hashes to decrypt names for UI
        all_doctors = sess.query(User).filter(User.role == "doctor").all()
        
        resolved_list = []  
        for doc in all_doctors:
            if doc.username_hash in hashes:
                real_name = decrypt_server_data(doc.encrypted_username)
                
                # DECRYPT ORGANIZATION
                real_org = "Unknown"
                if doc.organization:
                    try:
                        real_org = decrypt_server_data(doc.organization)
                    except:
                        real_org = "Error"
                
                # Append OBJECT instead of string
                resolved_list.append({
                    "username": real_name, 
                    "organization": real_org
                })
                
        return resolved_list  # Returns JSON list of objects

    finally:
        sess.close()
        
@router.post("/appointed_doctors_for_patient")
def appointed_doctors_for_patient(req: AppointedForPatientReq, request: Request):
    sess = Session()
    try:
        doctor = get_user_by_token(sess, req.token)
        if not doctor:
            log_audit("APPOINTED_DOCS_FOR_PATIENT", user="unknown", ip=request.client.host, result="FAILED - Invalid Token", level=logging.WARNING)
            raise HTTPException(401, "Invalid token")

        doc_name_log = decrypt_server_data(doctor.encrypted_username)

        if doctor.role != "doctor":
            log_audit("APPOINTED_DOCS_FOR_PATIENT", user=doc_name_log, ip=request.client.host, result="FAILED - Only doctors can use this endpoint", level=logging.WARNING)
            raise HTTPException(403, "Only doctors can use this endpoint")

        #  Hash input to find patient
        target_hash = hash_username(req.patient_username)
        patient = sess.query(User).filter(
            User.username_hash == target_hash,
            User.role == "patient"
        ).first()
        
        if not patient:
            log_audit("APPOINTED_DOCS_FOR_PATIENT", user=doc_name_log, target=req.patient_username, ip=request.client.host, result="FAILED - Patient not found", level=logging.WARNING)
            raise HTTPException(404, "Patient not found")

        # Check inclusion using doctor's stored hash
        if not patient.appointed_doctors or doctor.username_hash not in patient.appointed_doctors:
            log_audit("APPOINTED_DOCS_FOR_PATIENT", user=doc_name_log, target=req.patient_username, ip=request.client.host, result="FAILED - Not appointed for this patient", level=logging.WARNING)
            raise HTTPException(403, "Not appointed for this patient")

        return patient.appointed_doctors or []
    finally:
        sess.close()    

ALLOWED_EXTENSIONS = {'.pdf', '.txt', '.png', '.jpg', '.jpeg'}

@router.post("/upload")
def upload_record(req: UploadReq, request: Request):
    sess = Session()
    try:
        user = get_user_by_token(sess, req.token)
        
        # Upload when no user
        if not user:
            log_audit(
                "UPLOAD", 
                user="unknown", 
                role="unknown", 
                target_user=req.patient_username, 
                ip=request.client.host, 
                result="Failed - unauthorized", 
                user_agent=request.headers.get("user-agent"), 
                method=request.method, 
                path=request.url.path, 
                level=logging.INFO
            )
            raise HTTPException(401, "Unauthorized")
        
        # Decrypt Name for Logs
        user_name_log = decrypt_server_data(user.encrypted_username)
        target_patient_input = req.patient_username
        
        # Validate Extension
        client_ext = req.public_metadata.get("file_extension", "").lower()
        if client_ext not in ALLOWED_EXTENSIONS:
            log_audit(
                "UPLOAD", 
                user=user_name_log, 
                result=f"Blocked - Invalid extension {client_ext}", 
                ip=request.client.host, 
                level=logging.WARNING
            )
            raise HTTPException(400, f"File type {client_ext} is not allowed.")
        
        safe_public = {"type": "medical_record", "file_extension": client_ext}
        
        # Validate Input
        if not target_patient_input:
            log_audit(
                "UPLOAD", 
                user=user_name_log, 
                role=user.role, 
                target_user=req.patient_username, 
                ip=request.client.host, 
                result="Failed - missing patient in metadata", 
                user_agent=request.headers.get("user-agent"), 
                method=request.method, 
                path=request.url.path, 
                level=logging.INFO
            )
            raise HTTPException(400, "Missing patient in metadata")

        blob = base64.b64decode(req.encrypted_blob)
        
        # HASH THE TARGET for DB Operations
        hashed_target = hash_username(target_patient_input)

        # --- BRANCH 1: PATIENT UPLOAD (Direct Save) ---
        if user.role == "patient":
            # Strict Check: Patient's DB Hash vs Target Hash
            if hashed_target != user.username_hash:
                log_audit(
                    "UPLOAD", 
                    user=user_name_log, 
                    role=user.role, 
                    ip=request.client.host, 
                    result="Failed - mismatch patient", 
                    level=logging.INFO
                )
                raise HTTPException(401, "Patients can only upload to themselves")

            # Integrity Chain 
            prev = sess.query(MedicalRecord).filter(MedicalRecord.patient_username == user.username_hash)\
                                            .order_by(MedicalRecord.id.desc()).first()
            prev_hash = prev.record_hash if prev else "0" * 64
            
            meta = req.encrypted_metadata.encode() 
            sig_bytes = req.signature.encode() if req.signature else b""
            record_hash = hashlib.sha256(
                prev_hash.encode() + blob + meta + sig_bytes
            ).hexdigest()

            record = MedicalRecord(
                patient_username=user.username_hash, # Store Hash
                encrypted_metadata=req.encrypted_metadata,
                encrypted_blob=blob,
                public_metadata=safe_public,
                prev_hash=prev_hash,
                record_hash=record_hash,
                wrapped_keys=req.wrapped_keys,
                signature=req.signature
            )
            sess.add(record)
            sess.commit()
            
            log_audit(
                "UPLOAD", 
                user=user_name_log, 
                role=user.role, 
                result="SUCCESS, record uploaded", 
                ip=request.client.host, 
                user_agent=request.headers.get("user-agent"), 
                method=request.method, 
                path=request.url.path, 
                level=logging.INFO
            )
            return {"status": "ok", "record_hash": record_hash}

        # --- BRANCH 2: DOCTOR UPLOAD (Queue for Approval) ---
        elif user.role == "doctor":
            # Verify patient exists (Look up User by HASH)
            p_obj = sess.query(User).filter(
                User.username_hash == hashed_target, 
                User.role == "patient"
            ).first()
            if not p_obj: 
                log_audit(
                    "UPLOAD_REQ", 
                    user=user_name_log, 
                    target=target_patient_input, 
                    result="Failed - Patient not found", 
                    ip=request.client.host, 
                    level=logging.WARNING
                )
                raise HTTPException(404, "Patient not found")
            
            # Create Pending Request using HASHES
            pending = PendingRequest(
                requester=user.username_hash, # Doctor's Hash
                target=hashed_target,         # Patient's Hash
                req_type="upload_file",
                encrypted_metadata=req.encrypted_metadata,
                encrypted_blob=blob,
                public_metadata=safe_public,
                wrapped_keys=req.wrapped_keys,
                signature=req.signature
            )
            sess.add(pending)
            sess.commit()

            log_audit(
                "UPLOAD_REQ", 
                user=user_name_log, 
                role=user.role, 
                target=target_patient_input, 
                ip=request.client.host, 
                result="Queued for approval", 
                user_agent=request.headers.get("user-agent"), 
                method=request.method, 
                path=request.url.path, 
                level=logging.INFO
            )
            return {"status": "pending", "message": "File queued for patient approval"}

        else:
            log_audit(
                "UPLOAD", 
                user=user_name_log, 
                role=user.role, 
                ip=request.client.host, 
                result="Failed - invalid role", 
                level=logging.INFO
            )
            raise HTTPException(403, "Invalid Role")

    finally:
        sess.close()


@router.post("/list")
def list_records(req: ListReq, request: Request):
    detect_and_log_injection(req.patient_username or "", "patient_username", request)
    
    sess = Session()
    try:
        user = get_user_by_token(sess, req.token)
        if not user:
            log_audit(
                "LIST",
                user="unknown",
                role="unknown",
                ip=request.client.host,
                result="Failed, Invalid token",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING,
            )
            raise HTTPException(401, "Invalid token")
        
        # Decrypt Name for Logs
        user_name_log = decrypt_server_data(user.encrypted_username)

        # 1. Determine TARGET Hash
        target_hash = ""
        
        if user.role == "patient":
            target_hash = user.username_hash
        elif user.role == "doctor":
            if not req.patient_username:
                log_audit(
                    "LIST", 
                    user=user_name_log, 
                    role="unknown", 
                    ip=request.client.host, 
                    result="Failed, patient_username missing", 
                    level=logging.WARNING
                )
                raise HTTPException(400, "patient_username required for doctors")
            
            # Hash the input (Plaintext) to find the target (Hash)
            target_hash = hash_username(req.patient_username)
        else:
            log_audit(
                "LIST", 
                user=user_name_log, 
                role=user.role, 
                ip=request.client.host, 
                result="Failed, Invalid role", 
                level=logging.WARNING
            )
            raise HTTPException(403, "Invalid role")
        
        # 2. Query DB using HASH
        records = sess.query(MedicalRecord)\
                      .filter(MedicalRecord.patient_username == target_hash).all()

        # 3. Filter Keys for Requesting User (Use their stored Hash)
        user_hash = user.username_hash

        result = []
        for r in records:
            w_key = r.wrapped_keys.get(user_hash) if r.wrapped_keys else None
            if w_key:
                result.append({
                    "id": r.id,
                    "encrypted_metadata": r.encrypted_metadata,
                    "wrapped_key": w_key,
                    "signature": r.signature,
                    "public_metadata": r.public_metadata
                })

        log_audit(
            "LIST", 
            user=user_name_log, 
            role=user.role, 
            ip=request.client.host, 
            result="SUCCESS, records listed", 
            user_agent=request.headers.get("user-agent"), 
            method=request.method, 
            path=request.url.path, 
            level=logging.INFO
        )
        return result
    finally:
        sess.close()

@router.post("/download")
def download_record(req: DownloadReq, request: Request):
    detect_and_log_injection(str(req.record_id), "record_id", request)
    sess = Session()
    try:
        user = get_user_by_token(sess, req.token)
        if not user:
            log_audit(
                "DOWNLOAD", 
                user="unknown", 
                role="unknown", 
                result="FAILED - Invalid Token", 
                ip=request.client.host, 
                level=logging.WARNING
            )
            raise HTTPException(401, "Invalid token")
        
        user_name_log = decrypt_server_data(user.encrypted_username)

        # Lookup by ID
        record = sess.query(MedicalRecord).filter(MedicalRecord.id == req.record_id).first()
        if not record:
            log_audit(
                "DOWNLOAD", 
                user=user_name_log, 
                role=user.role, 
                record_id=req.record_id, 
                result="FAILED - Not found", 
                ip=request.client.host, 
                level=logging.WARNING
            )
            raise HTTPException(404, "Record not found")

        # Auth Check - Compare Hashes
        is_owner = (user.role == "patient" and record.patient_username == user.username_hash)
        
        # Check access using Hash key lookup
        wrapped_key = record.wrapped_keys.get(user.username_hash)
        
        if not is_owner and not wrapped_key:
             log_audit(
                 "DOWNLOAD", 
                 user=user_name_log, 
                 role=user.role, 
                 record_id=req.record_id, 
                 result="FAILED - Unauthorized", 
                 ip=request.client.host, 
                 level=logging.WARNING
             )
             raise HTTPException(403, "Forbidden")

        if not wrapped_key:
            log_audit(
                "DOWNLOAD", 
                user=user_name_log, 
                role=user.role, 
                record_id=req.record_id, 
                result="FAILED - No key", 
                ip=request.client.host, 
                level=logging.WARNING
            )
            raise HTTPException(403, "No access key")

        log_audit(
            "DOWNLOAD", 
            user=user_name_log, 
            role=user.role, 
            record_id=req.record_id, 
            ip=request.client.host, 
            result="SUCCESS, record downloaded", 
            level=logging.INFO
        )
        
        resp = {
            "encrypted_blob": base64.b64encode(record.encrypted_blob).decode(),
            "wrapped_key": wrapped_key,
            "encrypted_metadata": record.encrypted_metadata,
            "signature": record.signature,
            "public_metadata": record.public_metadata
        }

        if is_owner:
            resp["wrapped_keys"] = record.wrapped_keys

        return resp
    finally:
        sess.close()

@router.post("/share")
def share_record(req: ShareReq, request: Request):
    sess = Session()
    try:
        # 1. SECURE LOOKUP
        patient = get_user_by_token(sess, req.token)
        if not patient:
             log_audit("SHARE", user="unknown", ip=request.client.host, result="FAILED - Invalid Token", level=logging.WARNING)
             raise HTTPException(401, "Invalid token")
        
        patient_name_log = decrypt_server_data(patient.encrypted_username)

        if patient.role != "patient":
            log_audit(
                "SHARE", 
                user=patient_name_log, 
                record_id=req.record_id, 
                doctor=req.doctor_username, 
                role=patient.role, 
                ip=request.client.host, 
                result="Failed - unauthorized", 
                level=logging.WARNING
            )
            raise HTTPException(401, "Unauthorized")
        
        # 2. Check if doctor is appointed (using HASH)
        doctor_hash_check = hash_username(req.doctor_username)
        if doctor_hash_check not in (patient.appointed_doctors or []):
            log_audit(
                "SHARE", 
                user=patient_name_log, 
                record_id=req.record_id, 
                doctor=req.doctor_username, 
                role=patient.role, 
                ip=request.client.host, 
                result="Failed - doctor not appointed", 
                level=logging.WARNING
            )
            raise HTTPException(403, "Doctor not appointed")

        # 3. Lookup Record by ID and Patient Hash (Ownership check)
        record = sess.query(MedicalRecord).filter(
            MedicalRecord.id == req.record_id,
            MedicalRecord.patient_username == patient.username_hash 
        ).first()
        
        if not record:
            log_audit(
                "SHARE", 
                user=patient_name_log, 
                record_id=req.record_id, 
                doctor=req.doctor_username, 
                role=patient.role, 
                ip=request.client.host, 
                result="FAILED - Record not found", 
                level=logging.WARNING
            )
            raise HTTPException(404, "Record not found")

        if not record.wrapped_keys:
            record.wrapped_keys = {}
            
        # 4. Add doctor's key using HASH
        keys = dict(record.wrapped_keys)
        keys[doctor_hash_check] = req.wrapped_key
        record.wrapped_keys = keys
        
        sess.commit()
        
        log_audit(
            "SHARE", 
            user=patient_name_log, 
            record_id=req.record_id, 
            doctor=req.doctor_username, 
            role=patient.role, 
            ip=request.client.host, 
            result="SUCCESS, record shared", 
            level=logging.INFO
        )
        return {"status": "ok"}
    finally:
        sess.close()

        
@router.post("/delete")
def delete_record(req: DeleteReq, request: Request):
    sess = Session()
    try:
        # 1. SECURE LOOKUP
        user = get_user_by_token(sess, req.token)
        if not user: raise HTTPException(401, "Unauthorized")
        
        user_name_log = decrypt_server_data(user.encrypted_username)

        # 2. Find Record
        record = sess.query(MedicalRecord).filter(MedicalRecord.id == req.record_id).first()
        if not record: raise HTTPException(404, "Record not found")

        # 3. Check Ownership (Compare Hashes)
        if record.patient_username != user.username_hash:
            log_audit(
                "DELETE", 
                user=user_name_log, 
                ip=request.client.host, 
                result="FAILED - Not owner", 
                level=logging.WARNING
            )
            raise HTTPException(403, "Only the owner can delete records")

        # 4. Soft Delete (Tombstone)
        record.encrypted_blob = b"DELETED"
        record.encrypted_metadata = "DELETED"
        record.signature = "DELETED"
        record.wrapped_keys = {}
        record.public_metadata = {} 

        # 5. Integrity Chain Maintenance (Recalculate using new "DELETED" content)
        blob_bytes = record.encrypted_blob
        meta_bytes = record.encrypted_metadata.encode()
        sig_bytes  = record.signature.encode()
        new_hash = hashlib.sha256(record.prev_hash.encode() + blob_bytes + meta_bytes + sig_bytes).hexdigest()
        record.record_hash = new_hash

        sess.commit()

        log_audit(
            "DELETE", 
            user=user_name_log, 
            record_id=req.record_id, 
            result="Success", 
            ip=request.client.host, 
            user_agent=request.headers.get("user-agent"), 
            method=request.method, 
            path=request.url.path, 
            level=logging.INFO
        )
        return {"status": "ok"}
    finally:
        sess.close()
        

@router.post("/update")
def update_record(req: UpdateReq, request: Request):
    sess = Session()
    try:
        # 1. SECURE LOOKUP
        user = get_user_by_token(sess, req.token)
        if not user: raise HTTPException(401, "Unauthorized")
        
        user_name_log = decrypt_server_data(user.encrypted_username)

        # 2. Find Record
        record = sess.query(MedicalRecord).filter(MedicalRecord.id == req.record_id).first()
        if not record: raise HTTPException(404, "Record not found")

        # 3. Check Ownership (Strict: Hash vs Hash)
        if record.patient_username != user.username_hash:
             raise HTTPException(403, "Only owner can overwrite files directly")

        # 4. Integrity Chain Update
        import base64
        blob = base64.b64decode(req.encrypted_blob)
        meta = req.encrypted_metadata.encode()
        sig_bytes = req.signature.encode() if req.signature else b""
        new_hash = hashlib.sha256(record.prev_hash.encode() + blob + meta + sig_bytes).hexdigest()

        # 5. Apply Updates
        record.encrypted_blob = blob
        record.encrypted_metadata = req.encrypted_metadata
        record.record_hash = new_hash
        record.signature = req.signature
        record.wrapped_keys = req.wrapped_keys
        
        sess.commit()

        log_audit(
            "OVERWRITE", 
            user=user_name_log, 
            record_id=req.record_id, 
            result="Success", 
            ip=request.client.host, 
            user_agent=request.headers.get("user-agent"), 
            method=request.method, 
            path=request.url.path, 
            level=logging.INFO
        )
        return {"status": "ok"}
    finally:
        sess.close()