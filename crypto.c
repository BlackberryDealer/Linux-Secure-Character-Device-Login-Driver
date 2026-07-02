/* ================================================================
 * crypto.c - Cryptographic Subsystem and Side-Channel Shielding
 * CSC1107 Project 12 - Secure Character Device Login Driver
 *
 * Provides the driver's real cryptography:
 *   - compute_sha256()                SHA-256 via the kernel crypto API.
 *   - crypto_constant_time_compare()  constant-time buffer compare.
 *   - crypto_generate_token()         random token from the kernel CSPRNG.
 *   - bytes_to_hex() / hex_to_bytes() raw and hex conversion helpers.
 *
 * The constant-time compare and the CSPRNG are the two security-
 * critical pieces. They defend against timing side channels and
 * predictable tokens respectively.
 * ================================================================ */

#include "secure_internal.h"

/* ── Global defined here (declared extern in secure_internal.h) ── */
unsigned char stored_pw_hash[SHA256_DIGEST_BYTES];

/* ================================================================
 * compute_sha256() - SHA-256 digest of `data` into `digest`.
 *
 * Uses the kernel crypto API in the standard init / update / final
 * streaming pattern. `digest` must hold SHA256_DIGEST_BYTES (32).
 * Allocates a transform and descriptor per call and frees both before
 * returning. Returns 0 on success, negative errno on failure.
 *
 * Callers run this outside session_mutex where possible, since the
 * transform allocation below can sleep.
 * ================================================================ */
int compute_sha256(const unsigned char *data, size_t data_len,
                   unsigned char *digest)
{
    struct crypto_shash *tfm;
    struct shash_desc *sdesc;
    size_t desc_size;
    int ret;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "secure_dev: crypto_alloc_shash failed\n");
        return PTR_ERR(tfm);
    }

    desc_size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);
    sdesc = kmalloc(desc_size, GFP_KERNEL);
    if (!sdesc) {
        printk(KERN_ERR "secure_dev: kmalloc for sdesc failed\n");
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    sdesc->tfm = tfm;

    ret = crypto_shash_init(sdesc);
    if (ret) goto out;

    ret = crypto_shash_update(sdesc, data, data_len);
    if (ret) goto out;

    ret = crypto_shash_final(sdesc, digest);

out:
    kfree(sdesc);
    crypto_free_shash(tfm);
    return ret;
}

/* ================================================================
 * crypto_constant_time_compare() - timing-safe buffer compare.
 *
 * Wraps crypto_memneq(), which always scans the full length instead of
 * returning early on the first mismatch the way memcmp() does. That
 * fixed timing stops an attacker from recovering the stored hash byte
 * by byte by measuring how long each comparison takes.
 * Returns 0 if the buffers are equal, non-zero if they differ.
 * ================================================================ */
int crypto_constant_time_compare(const void *a, const void *b, size_t len)
{
    return crypto_memneq(a, b, len);
}

/* ================================================================
 * crypto_generate_token() - fill `out` with `len` random bytes.
 *
 * Uses get_random_bytes(), the kernel CSPRNG, so tokens are
 * unpredictable. This is deliberately not userspace rand(), whose
 * sequence an attacker could reproduce.
 * ================================================================ */
void crypto_generate_token(unsigned char *out, size_t len)
{
    get_random_bytes(out, len);
}

/* ================================================================
 * bytes_to_hex() - encode `len` raw bytes as a lowercase hex string.
 *
 * Example: {0xA3, 0x7F} becomes "a37f". The caller's `hex` buffer must
 * hold len*2 + 1 bytes (two chars per byte plus the terminator). The
 * token is handed to user space as hex rather than raw binary so it is
 * safe to print and copy as text.
 * ================================================================ */
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex)
{
    size_t i;
    for (i = 0; i < len; i++)
        sprintf(hex + i * 2, "%02x", bytes[i]);
    hex[len * 2] = '\0';
}

/* ================================================================
 * hex_to_bytes() - decode 2*len hex chars into `len` raw bytes.
 *
 * Reverse of bytes_to_hex: "a37f" becomes {0xA3, 0x7F}. Reads exactly
 * 2*len characters, so the caller must ensure the input is at least
 * that long and terminated. Rejects any non-hex character with -EINVAL,
 * which is what stops malformed token input from being decoded.
 * Returns 0 on success.
 * ================================================================ */
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        char hi_char = hex[2 * i];
        char lo_char = hex[2 * i + 1];
        unsigned char hi, lo;

        if (hi_char >= '0' && hi_char <= '9') hi = hi_char - '0';
        else if (hi_char >= 'a' && hi_char <= 'f') hi = hi_char - 'a' + 10;
        else if (hi_char >= 'A' && hi_char <= 'F') hi = hi_char - 'A' + 10;
        else return -EINVAL;

        if (lo_char >= '0' && lo_char <= '9') lo = lo_char - '0';
        else if (lo_char >= 'a' && lo_char <= 'f') lo = lo_char - 'a' + 10;
        else if (lo_char >= 'A' && lo_char <= 'F') lo = lo_char - 'A' + 10;
        else return -EINVAL;

        bytes[i] = (hi << 4) | lo;
    }
    return 0;
}
