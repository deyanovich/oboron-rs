"""oboron — string-in/string-out symmetric encryption + encoding.

Python bindings for the `oboron` Rust crate (the developer-facing
string-in/string-out layer over the `obcrypt` cryptographic core).

Docs: https://oboron.org/

Keys are 128-character hex strings — the canonical oboron key form,
what comes out of env vars, config files, and secrets managers. Every
codec constructor and free function takes the key as a plain ``str``.
A transitional 86-character base64 form is still accepted while the
`base64-keys` gate stays on in the core; it will be removed when the
core ships 1.0.

Quick start::

    import oboron

    key = oboron.generate_key()              # 128-char hex
    ob = oboron.AasvC32(key)
    obtext = ob.enc("hello, world")
    plaintext = ob.dec(obtext)
    assert plaintext == "hello, world"

Runtime-flexible style (`Ob`, format mutable after construction)::

    ob = oboron.Ob("aasv.b64", key)
    obtext = ob.enc("hello")
    ob.set_format("aags.c32")
    obtext2 = ob.enc("hello")

Multi-format style (`Omnib`, format per call, autodetect on decode)::

    omb = oboron.Omnib(key)
    obtext = omb.enc("hello", "aasv.b64")
    plaintext = omb.autodec(obtext)          # detects scheme + encoding

Schemes:

- ``aags`` — a-tier, deterministic, AES-GCM-SIV
- ``apgs`` — a-tier, probabilistic, AES-GCM-SIV
- ``aasv`` — a-tier, deterministic, AES-SIV (most general default)
- ``apsv`` — a-tier, probabilistic, AES-SIV
- ``upbc`` — u-tier (unauthenticated), probabilistic, AES-CBC
- ``zrbcx`` — z-tier (insecure, obfuscation only), deterministic AES-CBC

Encodings: ``b32`` (RFC 4648 base32), ``b64`` (URL-safe base64),
``c32`` (Crockford base32), ``hex``. Concatenated as ``scheme.encoding``,
e.g. ``aasv.c32``.

Exception hierarchy:

- ``OboronError`` — base class for all oboron exceptions
  - ``InvalidKey`` — bad hex / base64 / wrong length
  - ``InvalidFormat`` — unknown scheme / encoding / malformed format
  - ``EncryptionFailed`` — AEAD failure / empty plaintext
  - ``DecryptionFailed`` — tag / padding / obtext-decode / UTF-8
"""

from abc import ABC, abstractmethod
from typing import Protocol

from . import _oboron
from . import formats

__version__ = _oboron.__version__


# ============================================================================
# Protocols and base classes
# ============================================================================


class ObtextCodec(Protocol):
    """Structural protocol every codec satisfies (a/u-tier)."""

    def enc(self, plaintext: str) -> str: ...
    def dec(self, obtext: str) -> str: ...
    @property
    def format(self) -> str: ...
    @property
    def scheme(self) -> str: ...
    @property
    def encoding(self) -> str: ...


class OboronBase(ABC):
    """Abstract base class for all a/u-tier codec implementations.

    All a/u-tier codec classes (``AasvB32``, ``AasvC32``, etc.) plus
    ``Ob`` are registered as virtual subclasses, enabling
    ``isinstance()`` / ``issubclass()`` checks.

    Example::

        cipher = AasvC32(key=key)
        assert isinstance(cipher, OboronBase)

        def process(cipher: OboronBase) -> str:
            return cipher.enc("hello")
    """

    @abstractmethod
    def enc(self, plaintext: str) -> str: ...

    @abstractmethod
    def dec(self, obtext: str) -> str: ...

    @property
    @abstractmethod
    def format(self) -> str: ...

    @property
    @abstractmethod
    def scheme(self) -> str: ...

    @property
    @abstractmethod
    def encoding(self) -> str: ...

    @property
    @abstractmethod
    def key(self) -> str:
        """The 128-character hex key (canonical oboron form)."""
        ...

    @property
    @abstractmethod
    def key_hex(self) -> str:
        """Alias for ``.key``."""
        ...

    @property
    @abstractmethod
    def key_bytes(self) -> bytes:
        """Raw 64-byte key material."""
        ...


# ============================================================================
# Register Rust classes as virtual subclasses of OboronBase
# ============================================================================


def _register_if_present(*names: str) -> None:
    for name in names:
        cls = getattr(_oboron, name, None)
        if cls is not None:
            OboronBase.register(cls)


_register_if_present(
    "AagsC32", "AagsB32", "AagsB64", "AagsHex",
    "AasvC32", "AasvB32", "AasvB64", "AasvHex",
    "ApgsC32", "ApgsB32", "ApgsB64", "ApgsHex",
    "ApsvC32", "ApsvB32", "ApsvB64", "ApsvHex",
    "UpbcC32", "UpbcB32", "UpbcB64", "UpbcHex",
    "Mock1C32", "Mock1B32", "Mock1B64", "Mock1Hex",
    "Mock2C32", "Mock2B32", "Mock2B64", "Mock2Hex",
    "Ob",
)


# ============================================================================
# Re-exports
# ============================================================================

# Flexible interfaces
Ob = _oboron.Ob
Omnib = _oboron.Omnib

# Aags
AagsC32 = _oboron.AagsC32
AagsB32 = _oboron.AagsB32
AagsB64 = _oboron.AagsB64
AagsHex = _oboron.AagsHex

# Aasv
AasvC32 = _oboron.AasvC32
AasvB32 = _oboron.AasvB32
AasvB64 = _oboron.AasvB64
AasvHex = _oboron.AasvHex

# Apgs
ApgsC32 = _oboron.ApgsC32
ApgsB32 = _oboron.ApgsB32
ApgsB64 = _oboron.ApgsB64
ApgsHex = _oboron.ApgsHex

# Apsv
ApsvC32 = _oboron.ApsvC32
ApsvB32 = _oboron.ApsvB32
ApsvB64 = _oboron.ApsvB64
ApsvHex = _oboron.ApsvHex

# Upbc
UpbcC32 = _oboron.UpbcC32
UpbcB32 = _oboron.UpbcB32
UpbcB64 = _oboron.UpbcB64
UpbcHex = _oboron.UpbcHex

# Mock1 / Mock2 (testing)
Mock1C32 = _oboron.Mock1C32
Mock1B32 = _oboron.Mock1B32
Mock1B64 = _oboron.Mock1B64
Mock1Hex = _oboron.Mock1Hex
Mock2C32 = _oboron.Mock2C32
Mock2B32 = _oboron.Mock2B32
Mock2B64 = _oboron.Mock2B64
Mock2Hex = _oboron.Mock2Hex

# Utility functions
generate_key = _oboron.generate_key
generate_key_bytes = _oboron.generate_key_bytes
generate_secret = _oboron.generate_secret
generate_secret_bytes = _oboron.generate_secret_bytes

# Convenience functions
enc = _oboron.enc
dec = _oboron.dec
autodec = _oboron.autodec
enc_keyless = _oboron.enc_keyless
dec_keyless = _oboron.dec_keyless
autodec_keyless = _oboron.autodec_keyless

# Exceptions
OboronError = _oboron.OboronError
InvalidKey = _oboron.InvalidKey
InvalidFormat = _oboron.InvalidFormat
EncryptionFailed = _oboron.EncryptionFailed
DecryptionFailed = _oboron.DecryptionFailed


__all__ = [
    "__version__",
    # Base classes / protocols
    "OboronBase",
    "ObtextCodec",
    # Flexible interfaces
    "Ob",
    "Omnib",
    # Aags
    "AagsC32", "AagsB32", "AagsB64", "AagsHex",
    # Aasv
    "AasvC32", "AasvB32", "AasvB64", "AasvHex",
    # Apgs
    "ApgsC32", "ApgsB32", "ApgsB64", "ApgsHex",
    # Apsv
    "ApsvC32", "ApsvB32", "ApsvB64", "ApsvHex",
    # Upbc
    "UpbcC32", "UpbcB32", "UpbcB64", "UpbcHex",
    # Mock (testing)
    "Mock1C32", "Mock1B32", "Mock1B64", "Mock1Hex",
    "Mock2C32", "Mock2B32", "Mock2B64", "Mock2Hex",
    # Format constants module
    "formats",
    # Key / secret generation
    "generate_key",
    "generate_key_bytes",
    "generate_secret",
    "generate_secret_bytes",
    # Convenience functions
    "enc",
    "dec",
    "autodec",
    "enc_keyless",
    "dec_keyless",
    "autodec_keyless",
    # Exceptions
    "OboronError",
    "InvalidKey",
    "InvalidFormat",
    "EncryptionFailed",
    "DecryptionFailed",
]
