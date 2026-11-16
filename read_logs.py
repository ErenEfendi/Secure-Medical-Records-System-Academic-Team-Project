import os
import sys
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# FIX: Load .env from the SAME directory as this script (or strictly defined path)
# If read_logs.py is in the project root:
load_dotenv(".env")

# OR if you want it to be robust regardless of where you run it from:
# load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

def read_log_file(file_path):
    key = os.getenv("LOG_ENC_KEY")
    if not key:
        print("ERROR: LOG_ENC_KEY not found in .env!")
        print(f"Looking in: {os.path.abspath('.env')}")
        return

    try:
        cipher = Fernet(key.encode())
    except Exception as e:
        print(f"Key Error: {e}")
        return

    if not os.path.exists(file_path):
        print(f"Error: File not found -> {file_path}")
        return

    print(f"\n--- DECRYPTING LOG FILE: {file_path} ---\n")
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line: continue

                try:
                    # Format: ENCRYPTED_DATA | signature: SIGNATURE
                    if " | signature: " in line:
                        enc_content, _ = line.rsplit(" | signature: ", 1)
                        
                        # Decrypt
                        decrypted = cipher.decrypt(enc_content.encode()).decode()
                        print(f"[Line {line_num}] {decrypted}")
                    else:
                        print(f"[Line {line_num}] [FORMAT ERROR] Signature not found.")
                
                except Exception as e:
                    print(f"[Line {line_num}] [DECRYPT ERROR] {e}")

    except Exception as e:
        print(f"File reading error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python read_logs.py <log_file_path>")
        print("Example:   python read_logs.py server/logs/audit.log")
    else:
        read_log_file(sys.argv[1])