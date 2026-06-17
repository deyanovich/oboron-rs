/* Minimal C consumer of the oboron C ABI — the same round-trip the
 * Rust unit tests do, but across the real FFI boundary.
 *
 * Build & run:
 *   cargo build --release -p oboron-ffi
 *   cc examples/smoke.c -Iinclude -Ltarget/release -loboron_ffi -o /tmp/oboron-smoke
 *   LD_LIBRARY_PATH=target/release /tmp/oboron-smoke
 */
#include <stdio.h>
#include "oboron.h"

static int fail(const char *what) {
    fprintf(stderr, "%s: %s\n", what, oboron_last_error());
    return 1;
}

int main(void) {
    char *key = NULL, *obtext = NULL, *plaintext = NULL;

    if (oboron_generate_key(&key) != OBORON_OK)
        return fail("generate_key");

    if (oboron_enc("hello obsigil", "apsv.b64", key, &obtext) != OBORON_OK)
        return fail("enc");

    if (oboron_autodec(obtext, key, &plaintext) != OBORON_OK)
        return fail("autodec");

    printf("key     : %s\n", key);
    printf("obtext  : %s\n", obtext);
    printf("decoded : %s\n", plaintext);

    /* Every out-string is Rust-allocated — hand each back. */
    oboron_string_free(key);
    oboron_string_free(obtext);
    oboron_string_free(plaintext);
    return 0;
}
