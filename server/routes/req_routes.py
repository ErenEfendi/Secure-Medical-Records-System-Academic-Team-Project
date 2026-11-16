# server/routes/req_routes.py
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
import logging
from security.log_injections import detect_and_log_injection
from server.database import Session, User, PendingRequest, MedicalRecord
from server.routes.log_routes import log_audit
import hashlib
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv


load_dotenv()
key_str = os.getenv("SERVER_MASTER_KEY")
cipher = Fernet(key_str.encode())

router = APIRouter()



# --- Models ---
class TokenReq(BaseModel):
    token: str

class LinkReq(BaseModel):
    token: str
    patient_username: str

class ActionReq(BaseModel):
    token: str
    request_id: int

# --- Helper ---
def get_user(sess, token):
    h = hashlib.sha256(token.encode()).hexdigest()
    return sess.query(User).filter(User.token == h).first()


def hash_username(username: str) -> str:
    return hashlib.sha256(username.encode()).hexdigest()


def decrypt_server_data(token: str) -> str:
    return cipher.decrypt(token.encode()).decode()

# --- Routes ---

# 1. Doctor initiates a "Link" request
@router.post("/link_patient")
def request_link(req: LinkReq, request: Request):
    detect_and_log_injection(req.patient_username, "patient_username", request)
    
    sess = Session()
    try:
        doctor = get_user(sess, req.token)
        if not doctor or doctor.role != "doctor":
            log_audit(
                "REQ_LINK",
                user="unknown",
                role="unknown",
                ip=request.client.host,
                result="FAILED - Unauthorized",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING
            )
            raise HTTPException(401, "Unauthorized")

        # Get doctor name for logs (Decrypt)
        doc_name_log = decrypt_server_data(doctor.encrypted_username)

        # Hash input to find patient (User.username does not exist)
        target_hash = hash_username(req.patient_username)
        patient = sess.query(User).filter(User.username_hash == target_hash, User.role == "patient").first()
        
        if not patient:
            log_audit(
                "REQ_LINK",
                user=doc_name_log,
                role=doctor.role,
                target=req.patient_username,
                ip=request.client.host,
                result="FAILED - Patient not found",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING
            )
            raise HTTPException(404, "Patient not found")

        # Use stored username_hash
        if doctor.username_hash in (patient.appointed_doctors or []):
            log_audit(
                "REQ_LINK",
                user=doc_name_log,
                role = doctor.role,
                target=req.patient_username,
                result="FAILED - Already appointed",
                ip=request.client.host,
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING
            )
            raise HTTPException(400, "Already appointed")
        
        # Use stored hashes
        new_req = PendingRequest(
            requester=doctor.username_hash,
            target=patient.username_hash,
            req_type="link_doctor"
        )
        sess.add(new_req)
        sess.commit()

        log_audit(
            "REQ_LINK",
            user=doc_name_log,
            role=doctor.role,
            target=req.patient_username,
            result="SUCCESS - Request sent to patient",
            ip=request.client.host,
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.INFO
        )

        return {"status": "ok", "message": "Request sent to patient"}
    finally:
        sess.close()

# 2. Patient lists their pending requests
@router.post("/list")
def list_requests(req: TokenReq, request: Request):
    sess = Session()
    try:
        user = get_user(sess, req.token)
        if not user:
            log_audit(
                "REQ_LIST",
                user="unknown",
                role="unknown",
                ip=request.client.host,
                result="FAILED - Unauthorized",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING
            )
            raise HTTPException(401, "Unauthorized")
        
        # Use stored hash directly
        user_hash = user.username_hash

        reqs = sess.query(PendingRequest).filter(PendingRequest.target == user_hash).all()
        
        # Build Map to decrypt requester names
        all_users = sess.query(User).all()
        hash_to_name = {}
        for u in all_users:
            try:
                name = decrypt_server_data(u.encrypted_username)
                hash_to_name[u.username_hash] = name
            except:
                continue

        response_list = []
        for r in reqs:
            requester_name = hash_to_name.get(r.requester, "Unknown")
            
            response_list.append({
                "id": r.id,
                "requester": requester_name, 
                "type": r.req_type,
                "details": (r.public_metadata or {})
            })
            
        return response_list

    finally:
        sess.close()

# 3. Patient Approves
@router.post("/approve")
def approve_request(req: ActionReq, request: Request):
    sess = Session()
    try:
        user = get_user(sess, req.token)
        if not user:
            log_audit(
                "APPROVE",
                user="unknown",
                role="unknown",
                target="unknown",
                request_id=req.request_id,
                result="FAILED - Unauthorized",
                ip=request.client.host,
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING
            )
            raise HTTPException(401, "Unauthorized")
        
        user_name_log = decrypt_server_data(user.encrypted_username)
        user_hash = user.username_hash

        r = sess.query(PendingRequest).filter(
            PendingRequest.id == req.request_id,
            PendingRequest.target == user_hash
            ).first()
        
        if not r:
            log_audit(
                "APPROVE",
                user=user_name_log,
                role=user.role,
                target="unknown",
                request_id=req.request_id,
                result="FAILED - Request not found",
                ip=request.client.host,
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                level=logging.WARNING
            )
            raise HTTPException(404, "Request not found")

        # HANDLE LINK DOCTOR
        if r.req_type == "link_doctor":
            # Use hash for lookups
            patient = sess.query(User).filter(User.username_hash == user_hash).first()
            current_list = list(patient.appointed_doctors) if patient.appointed_doctors else []
            if r.requester not in current_list:
                current_list.append(r.requester)
                patient.appointed_doctors = current_list
                sess.commit()
        
        # HANDLE UPLOAD FILE
        elif r.req_type == "upload_file":
            # Use stored hash
            prev = sess.query(MedicalRecord).filter(MedicalRecord.patient_username == user_hash)\
                                            .order_by(MedicalRecord.id.desc()).first()
            prev_hash = prev.record_hash if prev else "0" * 64
            
            import hashlib
            blob = r.encrypted_blob
            meta = r.encrypted_metadata.encode()
            sig_bytes = r.signature.encode() if r.signature else b""
            
            rec_hash = hashlib.sha256(prev_hash.encode() + blob + meta + sig_bytes).hexdigest()
            
            final_public_meta = dict(r.public_metadata) if r.public_metadata else {}
            final_public_meta["uploader"] = r.requester
            
            safe_public = {"type": "medical_record"}
            # Copy over keys
            if r.public_metadata:
                 safe_public.update(r.public_metadata)
            safe_public["uploader"] = r.requester

            new_record = MedicalRecord(
                patient_username=user_hash, # Store Hash
                encrypted_metadata=r.encrypted_metadata,
                encrypted_blob=r.encrypted_blob,
                public_metadata=safe_public,  
                prev_hash=prev_hash,
                record_hash=rec_hash,
                wrapped_keys=r.wrapped_keys,
                signature=r.signature
            )
            sess.add(new_record)
            sess.commit()

        # Delete request after approval (cleanup)
        sess.delete(r)
        sess.commit()

        log_audit(
            "APPROVE",
            user=user_name_log,
            role=user.role,
            target=(r.requester if r.req_type == "link_doctor" else (r.target if r else "unknown")),            
            request_id=req.request_id,
            result="SUCCESS - Request Approved",
            ip=request.client.host,
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            level=logging.INFO
        )
        return {"status": "ok"}
    finally:
        sess.close()

# 4. Patient Rejects
@router.post("/reject")
def reject_request(req: ActionReq, request: Request):
    sess = Session()
    try:
        user = get_user(sess, req.token)
        if not user:
            log_audit(
                "REJECT",
                user="unknown",
                role="unknown",
                target="unknown",
                ip=request.client.host,
                result="FAILED - Unauthorized",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                request_id=req.request_id,
                level=logging.WARNING
            )
            raise HTTPException(401, "Unauthorized")
        
        user_name_log = decrypt_server_data(user.encrypted_username)
        user_hash = user.username_hash

        r = sess.query(PendingRequest).filter(
            PendingRequest.id == req.request_id,
            PendingRequest.target == user_hash
            ).first()
        
        if r:
            target_val = r.requester # save for log
            sess.delete(r)
            sess.commit()
            
            log_audit(
                "REJECT",
                user=user_name_log,
                role=user.role,
                target=target_val,            
                ip=request.client.host,
                result="SUCCESS",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                request_id=req.request_id,
                level=logging.INFO
            )
        else:
             log_audit(
                "REJECT",
                user=user_name_log,
                role=user.role,
                ip=request.client.host,
                result="Request not found or already deleted",
                user_agent=request.headers.get("user-agent"),
                method=request.method,
                path=request.url.path,
                request_id=req.request_id,
                level=logging.INFO
            )

        return {"status": "ok"}
    finally:
        sess.close()