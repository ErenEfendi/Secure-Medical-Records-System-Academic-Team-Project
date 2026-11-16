# server/routes/log_routes.py
from fastapi import APIRouter, HTTPException
from security.log_chain import ChainedLogger
import os
import logging
from dotenv import load_dotenv
from server.database import Session, User, MedicalRecord
import hashlib

router = APIRouter()

# Load .env from project root
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

# --- UPDATE: Load New Keys ---
LOG_ENC_KEY = os.getenv("LOG_ENC_KEY")
LOG_SIGN_KEY = os.getenv("LOG_SIGN_KEY")

if not LOG_ENC_KEY or not LOG_SIGN_KEY:
    raise RuntimeError("Missing LOG_ENC_KEY or LOG_SIGN_KEY in .env file.")

# Initialize Loggers with new keys
access_logger = ChainedLogger("server/logs/access.log", LOG_ENC_KEY, LOG_SIGN_KEY)
audit_logger  = ChainedLogger("server/logs/audit.log",  LOG_ENC_KEY, LOG_SIGN_KEY)

def log_access(action: str, level: int = logging.INFO, **fields):
    access_logger.log(action, level=level, **fields)

def log_audit(action: str, level: int = logging.INFO, **fields):
    audit_logger.log(action, level=level, **fields)

@router.get("/verify/access")
def verify_access():
    return {"valid": access_logger.verify_chain()}

@router.get("/verify/audit")
def verify_audit():
    return {"valid": audit_logger.verify_chain()}

@router.get("/verify/integrity")
def verify_database_integrity():
    # ... (Keep the rest of this function exactly as it is in your provided code)
    # ... It verifies the Database Hash Chain, which is separate from the Log Chain.
    sess = Session()
    report = {
        "status": "INTEGRITY_OK",
        "checked_patients": 0,
        "total_records": 0,
        "errors": []
    }
    
    try:
        # 1. Get all unique patients who have records
        patients = sess.query(MedicalRecord.patient_username).distinct().all()
        patients = [p[0] for p in patients]

        for patient_user in patients:
            report["checked_patients"] += 1
            
            # 2. Get records for this patient, ORDERED BY ID (Chronological)
            records = sess.query(MedicalRecord)\
                          .filter(MedicalRecord.patient_username == patient_user)\
                          .order_by(MedicalRecord.id.asc())\
                          .all()
            
            # 3. Verify Chain from Genesis
            expected_prev_hash = "0" * 64 # Genesis hash (First file)

            for rec in records:
                report["total_records"] += 1
                
                # Check A: Link Integrity (Does this record point to the correct previous one?)
                if rec.prev_hash != expected_prev_hash:
                    report["status"] = "TAMPERING_DETECTED"
                    report["errors"].append(f"BROKEN LINK: Record ID {rec.id} (Patient: {patient_user}). Expected prev '{expected_prev_hash[:8]}...', got '{rec.prev_hash[:8]}...'")
                    break 

                # Check B: Data Integrity (Has the content been modified?)
                blob_bytes = rec.encrypted_blob
                meta_bytes = rec.encrypted_metadata.encode()
                sig_bytes = rec.signature.encode() if rec.signature else b""
                
                calc_hash = hashlib.sha256(
                    expected_prev_hash.encode() + blob_bytes + meta_bytes + sig_bytes
                ).hexdigest()

                if calc_hash != rec.record_hash:
                    report["status"] = "TAMPERING_DETECTED"
                    report["errors"].append(f"DATA CORRUPTION: Record ID {rec.id} (Patient: {patient_user}). Hash mismatch.")
                
                expected_prev_hash = rec.record_hash

        return report

    except Exception as e:
        return {"status": "ERROR", "message": str(e)}
    finally:
        sess.close()
