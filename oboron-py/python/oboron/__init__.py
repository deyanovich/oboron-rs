"""oboron — string-in/string-out symmetric encryption + encoding.

Python bindings for the `oboron` Rust crate (the developer-facing
string-in/string-out layer over the `obcrypt` cryptographic core).

Docs: https://oboron.org/

Keys are 128-character hex strings — the canonical oboron key form,
what comes out of env vars, config files, and secrets managers. Every
codec constructor and free function takes the key as a plain ``str``.

Quick start::

    import oboron

    key = oboron.generate_key()              # 128-char hex
    ob = oboron.DsivC32(key)
    obtext = ob.enc("hello, world")
    plaintext = ob.dec(obtext)
    assert plaintext == "hello, world"

Runtime-flexible style (`Ob`, format mutable after construction)::

    ob = oboron.Ob("dsiv.b64", key)
    obtext = ob.enc("hello")
    ob.set_format("dgcmsiv.c32")
    obtext2 = ob.enc("hello")

Multi-format style (`Omnib`, format supplied per call)::

    omb = oboron.Omnib(key)
    obtext = omb.enc("hello", "dsiv.b64")
    plaintext = omb.dec(obtext, "dsiv.b64")  # scheme supplied, not detected

Schemes:

- ``dgcmsiv`` — deterministic, AES-GCM-SIV
- ``pgcmsiv`` — probabilistic, AES-GCM-SIV
- ``dsiv`` — deterministic, AES-SIV (most general default)
- ``psiv`` — probabilistic, AES-SIV

All four are authenticated. The unauthenticated / obfuscation
schemes are not part of oboron — they live in the separate ``obu``
package.

Encodings: ``b32`` (RFC 4648 base32), ``b64`` (URL-safe base64),
``c32`` (Crockford base32), ``hex``. Concatenated as ``scheme.encoding``,
e.g. ``dsiv.c32``.

Exception hierarchy:

- ``OboronError`` — base class for all oboron exceptions
  - ``InvalidKey`` — bad hex key / wrong length
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
    """Structural protocol every codec satisfies."""

    def enc(self, plaintext: str) -> str: ...
    def dec(self, obtext: str) -> str: ...
    @property
    def format(self) -> str: ...
    @property
    def scheme(self) -> str: ...
    @property
    def encoding(self) -> str: ...


class OboronBase(ABC):
    """Abstract base class for all oboron codec implementations.

    All codec classes (``DsivB32``, ``DsivC32``, etc.) plus ``Ob`` are
    registered as virtual subclasses, enabling ``isinstance()`` /
    ``issubclass()`` checks.

    Example::

        cipher = DsivC32(key=key)
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
    "DgcmsivC32", "DgcmsivB32", "DgcmsivB64", "DgcmsivHex",
    "DsivC32", "DsivB32", "DsivB64", "DsivHex",
    "PgcmsivC32", "PgcmsivB32", "PgcmsivB64", "PgcmsivHex",
    "PsivC32", "PsivB32", "PsivB64", "PsivHex",
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

# Dgcmsiv
DgcmsivC32 = _oboron.DgcmsivC32
DgcmsivB32 = _oboron.DgcmsivB32
DgcmsivB64 = _oboron.DgcmsivB64
DgcmsivHex = _oboron.DgcmsivHex

# Dsiv
DsivC32 = _oboron.DsivC32
DsivB32 = _oboron.DsivB32
DsivB64 = _oboron.DsivB64
DsivHex = _oboron.DsivHex

# Pgcmsiv
PgcmsivC32 = _oboron.PgcmsivC32
PgcmsivB32 = _oboron.PgcmsivB32
PgcmsivB64 = _oboron.PgcmsivB64
PgcmsivHex = _oboron.PgcmsivHex

# Psiv
PsivC32 = _oboron.PsivC32
PsivB32 = _oboron.PsivB32
PsivB64 = _oboron.PsivB64
PsivHex = _oboron.PsivHex

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

# Convenience functions
enc = _oboron.enc
dec = _oboron.dec
enc_keyless = _oboron.enc_keyless
dec_keyless = _oboron.dec_keyless

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
    # Dgcmsiv
    "DgcmsivC32", "DgcmsivB32", "DgcmsivB64", "DgcmsivHex",
    # Dsiv
    "DsivC32", "DsivB32", "DsivB64", "DsivHex",
    # Pgcmsiv
    "PgcmsivC32", "PgcmsivB32", "PgcmsivB64", "PgcmsivHex",
    # Psiv
    "PsivC32", "PsivB32", "PsivB64", "PsivHex",
    # Mock (testing)
    "Mock1C32", "Mock1B32", "Mock1B64", "Mock1Hex",
    "Mock2C32", "Mock2B32", "Mock2B64", "Mock2Hex",
    # Format constants module
    "formats",
    # Key generation
    "generate_key",
    "generate_key_bytes",
    # Convenience functions
    "enc",
    "dec",
    "enc_keyless",
    "dec_keyless",
    # Exceptions
    "OboronError",
    "InvalidKey",
    "InvalidFormat",
    "EncryptionFailed",
    "DecryptionFailed",
]
