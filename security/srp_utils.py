# security/srp_utils.py
import hashlib
import secrets

# --- SRP6a Constants (RFC 5054 2048-bit group) ---
N_HEX = '''AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4
A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179
A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041
D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E
688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861602790CA1094383'''

# Clean N for integer math
N = int("".join(N_HEX.split()), 16)
g = 2

def H(*args) -> int:
    """
    Helper hash function: SHA256(args...) -> int
    CRITICAL: Converts all Integers to lower-case HEX strings before hashing
    to match the JavaScript client implementation.
    """
    h = hashlib.sha256()
    for a in args:
        if isinstance(a, int):
            # Convert int to hex string (remove '0x'), ensure lower case
            val = hex(a)[2:].lower()
            
            # padding added
            # if len(val) is odd, prepend a '0' to make it even-length
            if len(val) % 2 == 1:
                val = '0' + val
            
            h.update(val.encode())
        elif isinstance(a, str):
            h.update(a.encode())
        elif isinstance(a, bytes):
            h.update(a)
    return int(h.hexdigest(), 16)

# k = H(N, g)
# We calculate k dynamically using the fixed H function to ensure alignment
k = H(N, g)

def calculate_verifier(salt: str, password: str) -> int:
    """v = g^x (mod N)"""
    # x = H(salt, password)
    x = H(salt, password) 
    return pow(g, x, N)