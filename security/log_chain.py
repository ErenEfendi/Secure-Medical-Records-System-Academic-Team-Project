import logging
import os
import base64
from datetime import datetime
from typing import Optional
from collections import deque
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

class ChainedLogger:
    def __init__(self, file_path: str, encryption_key_str: str, signing_key_str: str):
        """
        :param encryption_key_str: Base64 Fernet Key from .env (for Confidentiality)
        :param signing_key_str: PEM Private Key string from .env (for Non-Repudiation)
        """
        os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
        
        # Setup Logging Handler (No formatter, we write raw encrypted strings)
        logger_name = f"SecureLogger_{os.path.abspath(file_path)}"
        self.logger = logging.getLogger(logger_name)
        if not self.logger.handlers:
            handler = logging.FileHandler(file_path, mode="a", encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        self.file_path = file_path
        # Anchor File Path 
        self.head_path = file_path + ".head"

        # Setup Encryption (Confidentiality)
        if not encryption_key_str:
            raise ValueError("LOG_ENC_KEY is missing! Logs cannot be encrypted.")
        self.cipher = Fernet(encryption_key_str.encode())

        # Setup Signing (Non-Repudiation)
        if not signing_key_str:
             raise ValueError("LOG_SIGN_KEY is missing! Logs cannot be signed.")
        
        # Handle potential escaped newlines from .env
        clean_pem = signing_key_str.replace('\\n', '\n').encode()
        self.signing_key = serialization.load_pem_private_key(
            clean_pem, password=None, backend=default_backend()
        )

        # Recover Chain State
        self.prev_signature = self._recover_last_signature()

    def _recover_last_signature(self) -> bytes:
        """Reads the last line to get the last signature for chaining."""
        if not os.path.exists(self.file_path) or os.path.getsize(self.file_path) == 0:
            return b"\x00" * 64 # Genesis signature
        
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                # Efficiently read just the last line
                try:
                    last_line = deque(f, 1)[0]
                except IndexError:
                    return b"\x00" * 64
                
                content = last_line.strip()
                if " | signature: " in content:
                    _, hex_sig = content.rsplit(" | signature: ", 1)
                    return bytes.fromhex(hex_sig)
        except Exception as e:
            print(f"[LogChain] Warning: Could not recover last signature: {e}")
        
        return b"\x00" * 64

    def log(self, action: str, level: int = logging.INFO, **kwargs) -> None:
        # Build Plaintext Log
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
        log_prefix = f"{timestamp} - {logging.getLevelName(level)}"
        parts = [f"[{action}]"]
        for key in sorted(kwargs.keys()):
            parts.append(f'{key}="{kwargs[key]}"')
        
        plaintext_entry = f"{log_prefix} - {' '.join(parts)}"

        # Encrypt (Confidentiality)
        # Only the holder of LOG_ENC_KEY can read this.
        encrypted_entry = self.cipher.encrypt(plaintext_entry.encode()).decode()

        # Sign (Non-Repudiation + Integrity Chain)
        # We sign: (Previous_Signature + Encrypted_Current_Line)
        chain_input = self.prev_signature + encrypted_entry.encode()
        
        signature = self.signing_key.sign(
            chain_input,
            ec.ECDSA(hashes.SHA256())
        )

        # Write to Log File
        final_line = f"{encrypted_entry} | signature: {signature.hex()}"
        self.logger.log(level, final_line)

        # Update Memory State
        self.prev_signature = signature

        # We overwrite this file every time. It serves as the "Pointer" to the valid end.
        try:
            with open(self.head_path, "w", encoding="utf-8") as f:
                f.write(signature.hex())
        except Exception as e:
            print(f"CRITICAL: Could not write log anchor: {e}")

    def verify_chain(self) -> bool:
        """
        Verifies the chain integrity using the Public Key.
        Also checks against the .head anchor file to detect Tail Truncation.
        """
        if not os.path.exists(self.file_path): return True

        pub_key = self.signing_key.public_key()
        current_prev_sig = b"\x00" * 64
        last_read_signature = b"\x00" * 64 # Track the last valid signature we saw

        try:
            # Verify the File Chain
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line: continue
                    
                    if " | signature: " not in line: 
                        print(f"Malformat line {line_num}")
                        return False
                    
                    enc_content, sig_hex = line.rsplit(" | signature: ", 1)
                    signature = bytes.fromhex(sig_hex)

                    # Re-construct expected input: Prev_Sig + Encrypted_Content
                    expected_input = current_prev_sig + enc_content.encode()

                    # Verify Signature
                    try:
                        pub_key.verify(signature, expected_input, ec.ECDSA(hashes.SHA256()))
                    except Exception:
                        print(f"Integrity FAIL at line {line_num}!")
                        return False
                    
                    current_prev_sig = signature
                    last_read_signature = signature

            # Verify against Anchor File (Tail Truncation Check)
            if os.path.exists(self.head_path):
                with open(self.head_path, "r", encoding="utf-8") as f:
                    expected_head_hex = f.read().strip()
                    
                    #  Explicitly check if file is empty
                    if not expected_head_hex:
                        print("ALERT: Integrity Check Failed! Anchor (.head) file is EMPTY.")
                        return False

                    # Check for mismatch
                    if expected_head_hex != last_read_signature.hex():
                        print("ALERT: Tail Truncation Detected!")
                        print(f"  Anchor expects: {expected_head_hex[:16]}...")
                        print(f"  Log ends at:    {last_read_signature.hex()[:16]}...")
                        return False
            else:
                # Fail if file is completely missing
                print("ALERT: Integrity Check Failed! Anchor (.head) file is missing.")
                return False

            return True
        except Exception as e:
            print(f"Verification Error: {e}")
            return False