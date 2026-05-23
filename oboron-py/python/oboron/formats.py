"""Format string constants for Oboron. 

All constants follow the pattern:  {SCHEME}_{ENCODING}
- Schemes: AAGS, AASV, APGS, APSV, UPBC, ZRBCX, LEGACY, MOCK1, MOCK2
- Encodings:
  - B32 (RFC 4648 base32),
  - B64 (RFC 4648 base64url),
  - C32 (Crockford base32),
  - HEX (hexadecimal)

Example:
    >>> from oboron import formats
    >>> from oboron import Ob
    >>> 
    >>> ob = Ob(formats.AASV_B64, key)
    >>> ot = ob.enc("secret")
"""

# aags - deterministic AES-GCM-SIV (secure and authenticated)
AAGS_B32: str = "aags.b32"
AAGS_B64: str = "aags.b64"
AAGS_C32: str = "aags.c32"
AAGS_HEX: str = "aags.hex"

# aasv - deterministic AES-SIV (secure and authenticated, nonce-misuse resistant)
AASV_B32: str = "aasv.b32"
AASV_B64: str = "aasv.b64"
AASV_C32: str = "aasv.c32"
AASV_HEX: str = "aasv.hex"

# apgs - probabilistic AES-GCM-SIV (secure and authenticated)
APGS_B32: str = "apgs.b32"
APGS_B64: str = "apgs.b64"
APGS_C32: str = "apgs.c32"
APGS_HEX: str = "apgs.hex"

# apsv - probabilistic AES-SIV (secure and authenticated)
APSV_B32: str = "apsv.b32"
APSV_B64: str = "apsv.b64"
APSV_C32: str = "apsv.c32"
APSV_HEX: str = "apsv.hex"

# upbc - probabilistic AES-CBC (secure but not authenticated)
UPBC_B32: str = "upbc.b32"
UPBC_B64: str = "upbc.b64"
UPBC_C32: str = "upbc.c32"
UPBC_HEX: str = "upbc.hex"

# zrbcx - deterministic AES-CBC (insecure - obfuscation only)
ZRBCX_B32: str = "zrbcx.b32"
ZRBCX_B64: str = "zrbcx.b64"
ZRBCX_C32: str = "zrbcx.c32"
ZRBCX_HEX: str = "zrbcx.hex"

# Testing schemes (no encryption)
MOCK1_B32: str = "mock1.b32"
MOCK1_B64: str = "mock1.b64"
MOCK1_C32: str = "mock1.c32"
MOCK1_HEX: str = "mock1.hex"

MOCK2_B32: str = "mock2.b32"
MOCK2_B64: str = "mock2.b64"
MOCK2_C32: str = "mock2.c32"
MOCK2_HEX: str = "mock2.hex"

# Legacy (legacy - insecure - obfuscation only; backwards compatibility only - use zrbcx instead)
LEGACY: str = "legacy"

__all__ = [
    # aags
    "AAGS_B32", "AAGS_B64", "AAGS_C32", "AAGS_HEX",
    # aasv
    "AASV_B32", "AASV_B64", "AASV_C32", "AASV_HEX",
    # apgs
    "APGS_B32", "APGS_B64", "APGS_C32", "APGS_HEX",
    # apsv
    "APSV_B32", "APSV_B64", "APSV_C32", "APSV_HEX",
    # zrbcx
    "ZRBCX_B32", "ZRBCX_B64", "ZRBCX_C32", "ZRBCX_HEX",
    # upbc
    "UPBC_B32", "UPBC_B64", "UPBC_C32", "UPBC_HEX",
    # Legacy
    "LEGACY",
    # Testing
    "MOCK1_B32", "MOCK1_B64", "MOCK1_C32", "MOCK1_HEX",
    "MOCK2_B32", "MOCK2_B64", "MOCK2_C32", "MOCK2_HEX",
]
