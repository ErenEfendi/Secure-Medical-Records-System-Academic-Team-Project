# server/sanitization.py
import re
from fastapi import HTTPException

def validate_password_policy(password: str) -> None:
    """
    Validates password against security policy.
    Must contain at least one special character: !@#$%^&*()_+-=[]{}|;:,.<>?
    
    Raises HTTPException if policy is not met.
    """
    special_chars = r"!@#$%^&*()_+\-=\[\]{}|;:,.<>?"
    
    if not re.search(f"[{special_chars}]", password):
        raise HTTPException(
            400, 
            "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
        )