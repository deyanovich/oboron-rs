"""Smoke tests for inheritance and basic codec behavior.

Run with ``python -m oboron.test_inheritance`` after a successful
``maturin develop`` build.
"""

import oboron
from oboron import ztier


def test_oboron_base_isinstance():
    key = oboron.generate_key()

    aasv = oboron.AasvC32(key=key)
    assert isinstance(aasv, oboron.OboronBase)

    ob = oboron.Ob("aasv.b64", key=key)
    assert isinstance(ob, oboron.OboronBase)

    print("OK: a/u-tier isinstance(OboronBase)")


def test_ztier_base_isinstance():
    secret = oboron.generate_secret()  # 64-char hex

    z = ztier.ZrbcxC32(secret=secret)
    assert isinstance(z, ztier.ZtierBase)

    print("OK: z-tier isinstance(ZtierBase)")


def test_polymorphic_function():
    def encrypt_with_cipher(cipher: oboron.OboronBase, data: str) -> str:
        return cipher.enc(data)

    key = oboron.generate_key()
    aasv = oboron.AasvC32(key=key)
    apgs = oboron.ApgsC32(key=key)

    ot_a = encrypt_with_cipher(aasv, "hello")
    ot_p = encrypt_with_cipher(apgs, "hello")

    assert aasv.dec(ot_a) == "hello"
    assert apgs.dec(ot_p) == "hello"

    print("OK: polymorphic enc/dec over OboronBase")


def test_omnib_operations():
    key = oboron.generate_key()
    omnib = oboron.Omnib(key=key)

    ot_aasv = omnib.enc("test", "aasv.b64")
    ot_apgs = omnib.enc("test", "apgs.b64")

    assert omnib.autodec(ot_aasv) == "test"
    assert omnib.autodec(ot_apgs) == "test"

    print("OK: Omnib enc + autodec round-trip")


if __name__ == "__main__":
    test_oboron_base_isinstance()
    test_ztier_base_isinstance()
    test_polymorphic_function()
    test_omnib_operations()
    print("\nAll smoke tests passed.")
