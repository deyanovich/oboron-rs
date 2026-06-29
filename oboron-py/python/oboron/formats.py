"""Format string constants for Oboron. 

All constants follow the pattern:  {SCHEME}_{ENCODING}
- Schemes: DGCMSIV, DSIV, PGCMSIV, PSIV
- Encodings:
  - B32 (RFC 4648 base32),
  - B64 (RFC 4648 base64url),
  - C32 (Crockford base32),
  - HEX (hexadecimal)

Example:
    >>> from oboron import formats
    >>> from oboron import Ob
    >>> 
    >>> ob = Ob(formats.DSIV_B64, key)
    >>> ot = ob.enc("secret")
"""

# dgcmsiv - deterministic AES-GCM-SIV (secure and authenticated)
DGCMSIV_B32: str = "dgcmsiv.b32"
DGCMSIV_B64: str = "dgcmsiv.b64"
DGCMSIV_C32: str = "dgcmsiv.c32"
DGCMSIV_HEX: str = "dgcmsiv.hex"

# dsiv - deterministic AES-SIV (secure and authenticated, nonce-misuse resistant)
DSIV_B32: str = "dsiv.b32"
DSIV_B64: str = "dsiv.b64"
DSIV_C32: str = "dsiv.c32"
DSIV_HEX: str = "dsiv.hex"

# pgcmsiv - probabilistic AES-GCM-SIV (secure and authenticated)
PGCMSIV_B32: str = "pgcmsiv.b32"
PGCMSIV_B64: str = "pgcmsiv.b64"
PGCMSIV_C32: str = "pgcmsiv.c32"
PGCMSIV_HEX: str = "pgcmsiv.hex"

# psiv - probabilistic AES-SIV (secure and authenticated)
PSIV_B32: str = "psiv.b32"
PSIV_B64: str = "psiv.b64"
PSIV_C32: str = "psiv.c32"
PSIV_HEX: str = "psiv.hex"

__all__ = [
    # dgcmsiv
    "DGCMSIV_B32", "DGCMSIV_B64", "DGCMSIV_C32", "DGCMSIV_HEX",
    # dsiv
    "DSIV_B32", "DSIV_B64", "DSIV_C32", "DSIV_HEX",
    # pgcmsiv
    "PGCMSIV_B32", "PGCMSIV_B64", "PGCMSIV_C32", "PGCMSIV_HEX",
    # psiv
    "PSIV_B32", "PSIV_B64", "PSIV_C32", "PSIV_HEX",
]
