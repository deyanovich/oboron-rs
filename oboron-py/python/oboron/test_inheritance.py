"""Smoke tests for inheritance and basic codec behavior.

Run with ``python -m oboron.test_inheritance`` after a successful
``maturin develop`` build.
"""

import oboron


def test_oboron_base_isinstance():
    key = oboron.generate_key()

    dsiv = oboron.DsivC32(key=key)
    assert isinstance(dsiv, oboron.OboronBase)

    ob = oboron.Ob("dsiv.b64", key=key)
    assert isinstance(ob, oboron.OboronBase)

    print("OK: core isinstance(OboronBase)")


def test_polymorphic_function():
    def encrypt_with_cipher(cipher: oboron.OboronBase, data: str) -> str:
        return cipher.enc(data)

    key = oboron.generate_key()
    dsiv = oboron.DsivC32(key=key)
    pgcmsiv = oboron.PgcmsivC32(key=key)

    ot_d = encrypt_with_cipher(dsiv, "hello")
    ot_p = encrypt_with_cipher(pgcmsiv, "hello")

    assert dsiv.dec(ot_d) == "hello"
    assert pgcmsiv.dec(ot_p) == "hello"

    print("OK: polymorphic enc/dec over OboronBase")


def test_omnib_operations():
    key = oboron.generate_key()
    omnib = oboron.Omnib(key=key)

    ot_dsiv = omnib.enc("test", "dsiv.b64")
    ot_pgcmsiv = omnib.enc("test", "pgcmsiv.b64")

    # The scheme is supplied per dec call (no auto-detection).
    assert omnib.dec(ot_dsiv, "dsiv.b64") == "test"
    assert omnib.dec(ot_pgcmsiv, "pgcmsiv.b64") == "test"

    print("OK: Omnib enc + explicit-format dec round-trip")


if __name__ == "__main__":
    test_oboron_base_isinstance()
    test_polymorphic_function()
    test_omnib_operations()
    print("\nAll smoke tests passed.")
