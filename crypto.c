/* ================================================================
 * crypto.c — Cryptographic Subsystem & Side-Channel Shielding
 * CSC1107 Project 12 — Secure Character Device Login Driver
 *
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  MEMBER 4 — Cryptographic Subsystem & Side-Channel Shielding ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  Your Tasks:                                                 ║
 * ║   [TODO]  compute_sha256()                — kernel SHA-256   ║
 * ║   [TODO]  crypto_constant_time_compare()  — wraps memneq     ║
 * ║   [TODO]  crypto_generate_token()         — wraps get_random ║
 * ║   [TODO]  bytes_to_hex() / hex_to_bytes() — encoding helpers ║
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
 * │  MEMBER 4 TODO #1:  compute_sha256()                         │
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
    /* ── STUB: fills digest with zeros — same input always gives same
     *         output (passes the "deterministic" property) but is NOT
     *         actual SHA-256.  Member 4 replaces this. ── */
    memset(digest, 0, SHA256_DIGEST_BYTES);
    printk(KERN_INFO "secure_dev: [STUB] compute_sha256 (%zu bytes -> zeros)\n",
           data_len);
    return 0;
}

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 4 TODO #2:  crypto_constant_time_compare()           │
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
    /* ── STUB: returns 0 (equal) so login always succeeds in stub mode.
     *         Member 4 replaces with crypto_memneq(a, b, len). ── */
    printk(KERN_INFO "secure_dev: [STUB] crypto_constant_time_compare (%zu bytes -> 'equal')\n",
           len);
    return 0;
}

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 4 TODO #3:  crypto_generate_token()                  │
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
    /* ── STUB: fills with 0xAB pattern (NOT random!).  Replace. ── */
    memset(out, 0xAB, len);
    printk(KERN_INFO "secure_dev: [STUB] crypto_generate_token (%zu bytes of 0xAB)\n", len);
}

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 4 TODO #4:  bytes_to_hex()                           │
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
 * │  MEMBER 4 TODO #5:  hex_to_bytes()                           │
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
    /* ── STUB: fills with zeros.  Member 4 implements real decoding. ── */
    memset(bytes, 0, len);
    printk(KERN_INFO "secure_dev: [STUB] hex_to_bytes (%zu bytes -> zeros)\n", len);
    return 0;
}
