/* ================================================================
 * crypto.c — Cryptographic Subsystem & Side-Channel Shielding
 * CSC1107 Project 12 — Secure Character Device Login Driver
 *
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  MEMBER 4 — Cryptographic Subsystem & Side-Channel Shielding ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  Your Tasks:                                                 ║
 * ║   [DONE]  compute_sha256()                — kernel SHA-256   ║
 * ║   [DONE]  crypto_constant_time_compare()  — wraps memneq     ║
 * ║   [DONE]  crypto_generate_token()         — wraps get_random ║
 * ║   [DONE]  bytes_to_hex() / hex_to_bytes() — encoding helpers ║
 * ║                                                              ║
 * ║  Your "flashy" features for the report:                      ║
 * ║   - Native Kernel Crypto API: crypto_alloc_shash +           ║
 * ║     crypto_shash_update + crypto_shash_final (streaming API) ║
 * ║   - Timing Side-Channel Protection: crypto_memneq instead    ║
 * ║     of memcmp; constant time regardless of input             ║
 * ║                                                              ║
 * ║  ⚠ The stubs below let other members test their code, but    ║
 * ║    use FAKE crypto (all-zero hashes, etc.).  Your real       ║
 * ║    implementation gives the driver actual security.          ║
 * ╚══════════════════════════════════════════════════════════════╝
 * ================================================================ */

#include "secure_internal.h"

/* ── Global defined here (declared extern in secure_internal.h) ── */
unsigned char stored_pw_hash[SHA256_DIGEST_BYTES];

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 4 DONE #1:  compute_sha256()                         │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Compute the SHA-256 digest of `data` using the kernel's crypto API.
 *
 * Steps to implement (use the streaming update/final pattern):
 *   1. struct crypto_shash *tfm = crypto_alloc_shash("sha256", 0, 0);
 *      If IS_ERR(tfm): printk error and return PTR_ERR(tfm).
 *
 *   2. size_t desc_size = sizeof(struct shash_desc) +
 *                          crypto_shash_descsize(tfm);
 *      struct shash_desc *sdesc = kmalloc(desc_size, GFP_KERNEL);
 *      If NULL: crypto_free_shash(tfm); return -ENOMEM;
 *      sdesc->tfm = tfm;
 *
 *   3. ret = crypto_shash_init(sdesc);          // start the hash
 *      ret = crypto_shash_update(sdesc, data, data_len);  // feed data
 *      ret = crypto_shash_final(sdesc, digest); // get the result
 *      Check each return value.
 *
 *   4. kfree(sdesc); crypto_free_shash(tfm);
 *   5. Return 0 on success.
 *
 * Returns 0 on success, negative errno on failure.
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
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 4 DONE #2:  crypto_constant_time_compare()           │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Your "Timing Side-Channel Protection" feature.
 *
 * crypto_memneq() compares two buffers in CONSTANT time — it always
 * scans the full length regardless of where (or whether) the buffers
 * differ.  This stops attackers from learning the stored hash by
 * measuring how long the comparison takes.
 *
 * Steps:
 *   return crypto_memneq(a, b, len);
 *
 * (Yes, that's the whole function.  But explain the WHY in your report —
 * how memcmp() leaks via early exit, why this matters for password &
 * token verification, the byte-by-byte hash recovery attack.)
 *
 * Returns 0 if buffers are equal, non-zero if they differ.
 * ================================================================ */
int crypto_constant_time_compare(const void *a, const void *b, size_t len)
{
    return crypto_memneq(a, b, len);
}

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 4 DONE #3:  crypto_generate_token()                  │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Your "Cryptographic Token Generation" feature.  Fills `out` with
 * `len` bytes of cryptographically strong random data.
 *
 * Steps:
 *   get_random_bytes(out, len);
 *
 * (Again the whole function — but the report should explain the
 * difference between userspace rand() and kernel CSPRNG, and why
 * unpredictable session tokens matter for the security model.)
 * ================================================================ */
void crypto_generate_token(unsigned char *out, size_t len)
{
    get_random_bytes(out, len);
}

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 4 DONE #4:  bytes_to_hex()                           │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Convert raw bytes to a lowercase hex string.
 * Example: {0xA3, 0x7F} -> "a37f\0"
 *
 * Steps:
 *   for (size_t i = 0; i < len; i++)
 *       sprintf(hex + i * 2, "%02x", bytes[i]);
 *   hex[len * 2] = '\0';
 *
 * (This is simple enough you can implement it now — but explain
 * in your report why returning a hex string to user space is safer
 * than returning raw binary bytes.)
 * ================================================================ */
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex)
{
    /* This stub IS a real implementation — bytes_to_hex is trivial. */
    size_t i;
    for (i = 0; i < len; i++)
        sprintf(hex + i * 2, "%02x", bytes[i]);
    hex[len * 2] = '\0';
}

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 4 DONE #5:  hex_to_bytes()                           │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Reverse of bytes_to_hex.  "a37f" -> {0xA3, 0x7F}.
 *
 * Steps:
 *   for (size_t i = 0; i < len; i++) {
 *       Parse hex[2*i]   as high nibble  ('0'-'9', 'a'-'f', 'A'-'F')
 *       Parse hex[2*i+1] as low nibble
 *       If either character is not valid hex: return -EINVAL.
 *       bytes[i] = (hi << 4) | lo;
 *   }
 *   return 0;
 *
 * Returns 0 on success, -EINVAL if hex contains a non-hex character.
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
