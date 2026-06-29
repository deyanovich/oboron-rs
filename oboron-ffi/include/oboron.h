/* oboron C ABI — committed reference header.
 *
 * Canonical surface that FFI consumers (Perl, C#, Java/Panama, C, …)
 * bind against. Regenerate from the Rust source with:
 *   cbindgen --config cbindgen.toml --output include/oboron.h
 *
 * Contract (see src/lib.rs for the full text):
 *  - Inputs are NUL-terminated UTF-8 (const char *).
 *  - Each `out` string is heap-allocated and owned by the caller,
 *    who MUST release it with oboron_string_free(); never libc free.
 *  - Return is a status code: 0 = OBORON_OK, < 0 = FFI-layer fault,
 *    > 0 = oboron error. On any nonzero return do NOT read *out;
 *    fetch a message with oboron_last_error().
 */
#ifndef OBORON_H
#define OBORON_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OBORON_OK 0
#define OBORON_ERR_NULL_ARG -1
#define OBORON_ERR_UTF8 -2
#define OBORON_ERR_INTERIOR_NUL -3
#define OBORON_ERR_PANIC -4
#define OBORON_ERR_OBORON 1

/* Borrow this thread's last error message (NUL-terminated), or NULL
 * if the last call succeeded. Valid only until the next oboron_*
 * call on this thread; do not free. */
const char *oboron_last_error(void);

/* Release a string returned through an `out` parameter. NULL is a
 * no-op; double-free or a foreign pointer is undefined behavior. */
void oboron_string_free(char *s);

/* Generate a fresh random key as a 128-char hex string. */
int32_t oboron_generate_key(char **out);

/* Encrypt `plaintext` under `format` (e.g. "psiv.b64") and `key`. */
int32_t oboron_enc(const char *plaintext, const char *format,
                   const char *key, char **out);

/* Decrypt with an explicit `format` and `key`. */
int32_t oboron_dec(const char *obtext, const char *format,
                   const char *key, char **out);

#ifdef OBORON_KEYLESS
/* Keyless (public built-in key) variants — no secrecy or
 * authentication against an adversary. */
int32_t oboron_enc_keyless(const char *plaintext, const char *format,
                           char **out);
int32_t oboron_dec_keyless(const char *obtext, const char *format,
                           char **out);
#endif /* OBORON_KEYLESS */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OBORON_H */
