# server/database.py
from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, JSON, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
import os
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username_hash = Column(String, unique=True, nullable=False) # For Lookup (Blind Index)
    encrypted_username = Column(String, nullable=False)
    role = Column(String, nullable=False)
    srp_salt = Column(String, nullable=False)
    srp_verifier = Column(String, nullable=False)
    pub_key = Column(LargeBinary, nullable=False)
    encrypted_priv_key = Column(String, nullable=True)
    mfa_secret = Column(String, nullable=True)
    appointed_doctors = Column(JSON, default=list)
    organization = Column(String)
    dob = Column(String, nullable=True)
    token = Column(String, nullable=True)

class MedicalRecord(Base):
    __tablename__ = "records"
    id = Column(Integer, primary_key=True)
    patient_username = Column(String, nullable=False)
    
    # Encrypted blob for sensitive data (filename, date, content)
    encrypted_metadata = Column(String, nullable=False)
    encrypted_blob = Column(LargeBinary, nullable=False)
    public_metadata = Column(JSON, nullable=False)
    prev_hash = Column(String, nullable=True)
    record_hash = Column(String, nullable=True)
    wrapped_keys = Column(JSON, nullable=True)
    # Stores Base64 signature of (encrypted_metadata + encrypted_blob)
    signature = Column(String, nullable=False)

# --- NEW TABLE: PENDING REQUESTS ---
class PendingRequest(Base):
    __tablename__ = "pending_requests"
    id = Column(Integer, primary_key=True)
    requester = Column(String, nullable=False) # The Doctor
    target = Column(String, nullable=False)    # The Patient
    req_type = Column(String, nullable=False)  # "link_doctor" or "upload_file"
    
    # For File Uploads (Temporary Storage)
    encrypted_metadata = Column(String, nullable=True)
    encrypted_blob = Column(LargeBinary, nullable=True)
    public_metadata = Column(JSON, nullable=True)
    wrapped_keys = Column(JSON, nullable=True)
    signature = Column(String, nullable=True)
    
    status = Column(String, default="pending") # pending, approved, rejected

DB_PATH = "server/data.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)