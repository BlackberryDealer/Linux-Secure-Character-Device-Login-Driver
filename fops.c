/* ================================================================
 * fops.c — File Operations & User-Kernel Isolation Matrix
 * CSC1107 Project 12 — Secure Character Device Login Driver
 *
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  MEMBER 2 — File Operations & User-Kernel Isolation Matrix   ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  Implemented:                                               ║
 * ║   [DONE]  secure_open()    — alloc session via Member 3      ║
 * ║   [DONE]  secure_release() — free session via Member 3       ║
 * ║   [DONE]  secure_read()    — auth gate + copy_to_user        ║
 * ║   [DONE]  secure_write()   — auth gate + copy_from_user      ║
 * ║   [DONE]  secure_ioctl()   — dispatch LOGIN/LOGOUT/STATUS/   ║
 * ║                              GET_TOKEN/VERIFY_TOKEN cases    ║
 * ║                                                              ║
 * ║  Your "flashy" features for the report:                      ║
 * ║   - Strict Security Gates: every read/write checks session,  ║
 * ║     returns -EACCES + logs [SECURITY ALERT] if not authed    ║
 * ║   - User-Kernel Containment: bounded min() + copy_*_user()   ║
 * ║                                                              ║
 * ║  You will call functions from:                               ║
 * ║     session.c  — session field access                        ║
 * ║     crypto.c   — compute_sha256, crypto_constant_time_compare║
 * ║                  crypto_generate_token, bytes_to_hex,        ║
 * ║                  hex_to_bytes                                ║
 * ║     core.c     — atomic_inc(&failed_login_count)             ║
 * ╚══════════════════════════════════════════════════════════════╝
 * ================================================================ */

#include "secure_internal.h"

/* Fixed message returned to authenticated reads */
static const char kernel_msg[] = "Hello World from the kernel space\n";

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 2 TODO #1:  secure_open()                            │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Called automatically when a user-space program opens /dev/secure_dev.
 *
 * Steps to implement:
 *   1. struct session_entry *sess = session_alloc();   // Member 3
 *      If NULL: return -ENOMEM.
 *   2. file->private_data = sess;
 *      (This attaches the session to THIS open file descriptor.)
 *   3. printk(KERN_INFO ... "Device opened by PID %d", current->pid);
 *   4. return 0;
 * ================================================================ 
 * secure_open()
 * * PURPOSE: 
 * Handles the initialization of a fresh communication session when a 
 * user-space process opens the character device file (/dev/secure_dev).
 *
 * MECHANICS:
 * Dynamically allocates a new isolated session tracking block using 
 * the custom allocator `session_alloc()`. The memory block address is 
 * bound directly to the file descriptor configuration context via the 
 * kernel file structure (`file->private_data`). 
 * * SECURITY/ISOLATION DESIGN:
 * Ephemeral Session Tracking. By tying the authentication context strictly 
 * to a localized open file handle structure rather than global process tracking 
 * (like a PID map), the kernel naturally forces a clean, state-free isolation 
 * model. New device open events automatically begin in an unauthenticated state.
 * ================================================================ */

static int secure_open(struct inode *inode, struct file *file)
{
    struct session_entry *sess = session_alloc();
    if (!sess) return -ENOMEM;
    file->private_data = sess;
    printk(KERN_INFO "secure_dev: Device opened by PID %d\n", current->pid);
    return 0;
}

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 2 TODO #2:  secure_release()                         │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Called automatically when user-space closes the device.
 *
 * Steps:
 *   1. struct session_entry *sess = file->private_data;
 *   2. If sess != NULL: session_free(sess);   // Member 3
 *   3. file->private_data = NULL;
 *   4. printk and return 0.
 * ================================================================ 
 * * secure_release()
 * * PURPOSE: 
 * Cleans up and destroys session contexts when a user-space process 
 * closes its file descriptor handle to the character device.
 *
 * MECHANICS:
 * Retrieves the bound session reference stored in `file->private_data`. 
 * If a session is valid, it calls `session_free()` to recycle the 
 * memory block and then clears out the reference (`NULL`) to defend 
 * against dangling pointer vulnerabilities.
 * * SECURITY/ISOLATION DESIGN:
 * Immediate Destructive Sanitization. Ensures that credentials, temporary hashes, 
 * and authentication flags are completely cleared out of active memory 
 * the exact millisecond the file descriptor lifespan drops, avoiding 
 * authorization-leak or session-hijacking opportunities across processes.
 * ================================================================ */

static int secure_release(struct inode *inode, struct file *file)
{
    struct session_entry *sess = file->private_data;
    if (sess) {
        session_free(sess);
        file->private_data = NULL;
    }
    printk(KERN_INFO "secure_dev: Device closed by PID %d\n", current->pid);
    return 0;
}
/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 2 TODO #3:  secure_read()                            │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Your "Strict Security Gate" feature.
 *
 * Steps:
 *   1. struct session_entry *sess = file->private_data;
 *   2. mutex_lock(&session_mutex);
 *   3. If !sess || !sess->authenticated:
 *        printk(KERN_WARNING ... "[SECURITY ALERT] Unauthorized READ by PID %d");
 *        mutex_unlock(&session_mutex);
 *        return -EACCES;
 *   4. mutex_unlock(&session_mutex);
 *   5. Compute how many bytes to copy:
 *        size_t msg_len = sizeof(kernel_msg) - 1;
 *        If *ppos >= msg_len: return 0;  (EOF)
 *        size_t to_copy = min(count, msg_len - *ppos);
 *   6. copy_to_user(user_buf, kernel_msg + *ppos, to_copy);
 *      On failure: return -EFAULT;
 *   7. *ppos += to_copy; return to_copy;
 * ================================================================ 
 * * secure_read()
 * * PURPOSE: 
 * Provides an authorized user-space interface to safely retrieve protected data 
 * ("Hello World from the kernel space") out of the kernel space buffer.
 *
 * MECHANICS:
 * First checks authentication under structural locks. If authenticated, it manages 
 * standard file position offsets (`ppos`) against the string bounds, scales 
 * the chunk safely using `min()`, and transfers the buffer downstream using `copy_to_user()`.
 * * SECURITY/ISOLATION DESIGN:
 * 1. Strict Security Gate: Validates `sess->authenticated` inside an atomic lock. 
 * Unauthenticated hits drop straight out, returning `-EACCES` and throwing a alert.
 * 2. User-Kernel Containment: Rejects raw pointer bounds math. Relies entirely 
 * on a constrained `min()` verification layer and `copy_to_user()` to ensure 
 * that user apps can never trick the kernel into leaking random ring-0 memory spaces.
 * ================================================================ */



static ssize_t secure_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
    struct session_entry *sess = file->private_data;
    size_t msg_len = sizeof(kernel_msg) - 1;
    size_t to_copy;

    /* ── STRICT SECURITY GATE ── */
    mutex_lock(&session_mutex);
    if (!sess || !sess->authenticated) {
        printk(KERN_WARNING "secure_dev: [SECURITY ALERT] Unauthorized READ attempt by PID %d\n", current->pid);
        mutex_unlock(&session_mutex);
        return -EACCES; /* Return Permission Denied to user space */
    }
    mutex_unlock(&session_mutex);

    /* Boundary containment and EOF management */
    if (*ppos >= (loff_t)msg_len)
        return 0;

    to_copy = min(count, msg_len - (size_t)*ppos);
    if (copy_to_user(user_buf, kernel_msg + *ppos, to_copy))
        return -EFAULT;

    *ppos += to_copy;
    return to_copy;
    }




/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 2 TODO #4:  secure_write()                           │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Steps:
 *   1. struct session_entry *sess = file->private_data;
 *   2. mutex_lock(&session_mutex);
 *   3. If !sess || !sess->authenticated:
 *        printk("[SECURITY ALERT] Unauthorized WRITE by PID %d");
 *        mutex_unlock; return -EACCES;
 *   4. Save username from sess to a local buffer for logging.
 *   5. mutex_unlock;
 *   6. size_t write_len = min(count, (size_t)(MAX_BUFFER_SIZE - 1));
 *      char tmp[MAX_BUFFER_SIZE];
 *      copy_from_user(tmp, user_buf, write_len); — return -EFAULT on fail
 *      tmp[write_len] = '\0';
 *   7. printk to log what user wrote, return write_len.
 * ================================================================ 
 * * secure_write()
 * * PURPOSE: 
 * Lets authorized users push data upstream from user-space to a protected 
 * isolated buffer inside the kernel environment.
 *
 * MECHANICS:
 * Verifies access privileges, pulls down user-space string sequences into a localized, 
 * null-bounded kernel buffer (`tmp`) via `copy_from_user()`, and logs the action.
 * * SECURITY/ISOLATION DESIGN:
 * 1. Non-Leaking Concurrency: Safely makes a quick local stack duplicate of the 
 * session username string (`strncpy`) while inside the lock boundary. This ensures 
 * the lock can be quickly released before doing expensive IO work like printing or 
 * copying from user-space, avoiding kernel deadlocks.
 * 2. Strict Input Hardening: Constrains total readable sequence size down using 
 * `min(count, MAX_BUFFER_SIZE - 1)`. Hard-terminates the array offset manually with `\0` 
 * to completely eliminate buffer overrun and malicious string termination attacks.
 * ================================================================ */



 static ssize_t secure_write(struct file *file, const char __user *user_buf,
                             size_t count, loff_t *ppos)
{
    struct session_entry *sess = file->private_data;
    char tmp[MAX_BUFFER_SIZE];
    char log_user[MAX_USERNAME_LEN] = "Unknown";
    size_t write_len;

    /* ── STRICT SECURITY GATE ── */
    mutex_lock(&session_mutex);
    if (!sess || !sess->authenticated) {
        printk(KERN_WARNING "secure_dev: [SECURITY ALERT] Unauthorized WRITE attempt by PID %d\n", current->pid);
        mutex_unlock(&session_mutex);
        return -EACCES; /* Return Permission Denied to user space */
    }
    /* Safely copy username for logging out-of-lock */
    strncpy(log_user, sess->username, sizeof(log_user) - 1);
    log_user[sizeof(log_user) - 1] = '\0';
    mutex_unlock(&session_mutex);

    /* User-Kernel Containment */
    write_len = min(count, (size_t)(MAX_BUFFER_SIZE - 1));

    if (copy_from_user(tmp, user_buf, write_len))
        return -EFAULT;

    tmp[write_len] = '\0';

    printk(KERN_INFO "secure_dev: User '%s' (PID %d) wrote: \"%s\"\n", log_user, current->pid, tmp);
    return write_len;
}

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 2 TODO #5:  secure_ioctl() — the big one             │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Dispatch the 5 commands defined in secure_driver.h.
 *
 * General pattern for each case:
 *   - Get the session: struct session_entry *sess = file->private_data;
 *   - mutex_lock(&session_mutex)
 *   - Validate, do work, optionally copy_to/from_user
 *   - mutex_unlock and return
 *
 * Specific cases:
 *
 * case SECURE_IOCTL_LOGIN:
 *   1. copy_from_user(&creds, arg, sizeof(creds))
 *   2. Null-terminate creds.username and creds.password
 *   3. compute_sha256(creds.password, ..., input_hash)   // crypto.c
 *   4. user_match = strncmp(creds.username, param_username, ...) == 0;
 *      hash_match = (crypto_constant_time_compare(input_hash,
 *                       stored_pw_hash, SHA256_DIGEST_BYTES) == 0);
 *      Use BITWISE & (not &&) to avoid short-circuit timing leak:
 *        if (user_match & hash_match) { ...success... }
 *        else { atomic_inc(&failed_login_count); ...failure... }
 *   5. memset(creds.password, 0, ...) to wipe plaintext
 *
 * case SECURE_IOCTL_LOGOUT:
 *   Clear sess->authenticated, sess->token_valid, sess->username,
 *   sess->token_hash.
 *
 * case SECURE_IOCTL_STATUS:
 *   int status = sess->authenticated ? 1 : 0;
 *   copy_to_user(arg, &status, sizeof(int));
 *
 * case SECURE_IOCTL_GET_TOKEN:
 *   If !sess->authenticated: return -EACCES.
 *   crypto_generate_token(raw_token, TOKEN_RAW_BYTES);   // crypto.c
 *   compute_sha256(raw_token, ..., sess->token_hash);
 *   sess->token_valid = true;
 *   bytes_to_hex(raw_token, TOKEN_RAW_BYTES, hex);
 *   copy_to_user the hex back to user.
 *   memset raw_token to wipe it.
 *
 * case SECURE_IOCTL_VERIFY_TOKEN:
 *   If !sess->token_valid: return -EINVAL.
 *   copy_from_user the hex from user
 *   hex_to_bytes(...) to get raw bytes
 *   compute_sha256(bytes, ..., presented_hash)
 *   crypto_constant_time_compare(presented_hash, sess->token_hash, ...)
 *   == 0 means verified.
 *
 * default:
 *   return -ENOTTY;
 * ================================================================ 
 * * secure_ioctl()
 * * PURPOSE: 
 * The central command-and-control dispatch system. Interprets custom ioctl() 
 * interface requests passed from user-space applications to manage core state 
 * transitions (Logins, Logouts, Status checking, Token Generation, Token Validation).
 * * SECURITY/ISOLATION DESIGN STRATEGIES PER CASE BRANCH:
 * * SECURE_IOCTL_LOGIN:
 * - Constant-Time Hashing Strategy: Immediately hashes incoming passwords via 
 * `compute_sha256()`.
 * - Mitigation Against Timing Attacks: Performs authentication matching logic by 
 * linking string validations with a bitwise AND operator (`&`) instead of a 
 * short-circuiting logical AND (`&&`). It calls `crypto_constant_time_compare()`, 
 * guaranteeing that execution time remains completely fixed regardless of how many 
 * password characters are correct. This blocks timing side-channel exploits.
 * - Memory Sanitization: Uses an immediate zero-fill `memset` over password stack buffers 
 * to ensure raw keys do not sit exposed in memory.
 * * SECURE_IOCTL_LOGOUT:
 * - Full State Invalidation: Safely resets session variables and uses a zeros-out memory 
 * wipe (`memset`) on old tokens/usernames to guarantee zero data remanence.
 * * SECURE_IOCTL_STATUS:
 * - Thread-Safe Querying: Safely returns a flag identifying whether the current file handle 
 * session is authenticated.
 * * SECURE_IOCTL_GET_TOKEN:
 * - Multi-Factor Session Generation: Generates highly cryptographic random tokens using 
 * `crypto_generate_token()`, hashes it to serve as a session verification signature 
 * (`sess->token_hash`), converts the raw binary array into printable safe data using 
 * `bytes_to_hex()`, and safely copies the hex data to user space.
 * * SECURE_IOCTL_VERIFY_TOKEN:
 * - Secure Two-Way Authentication: Validates a user-space token without revealing the 
 * stored secret. Pulls down the hex data, decodes it back to raw bytes using `hex_to_bytes()`, 
 * computes its SHA-256 footprint, and runs a constant-time comparison against the 
 * pre-registered signature.
 * ================================================================ */
static long secure_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct session_entry *sess = file->private_data;
    void __user *argp = (void __user *)arg;

    if (!sess) return -EINVAL;

    switch (cmd) {
    case SECURE_IOCTL_LOGIN: {
        struct login_data creds;
        unsigned char input_hash[SHA256_DIGEST_BYTES];
        int user_match, hash_match;

        if (copy_from_user(&creds, argp, sizeof(creds))) return -EFAULT;
        creds.username[MAX_USERNAME_LEN - 1] = '\0';
        creds.password[MAX_PASSWORD_LEN - 1] = '\0';

        if (compute_sha256((unsigned char *)creds.password,
                           strlen(creds.password), input_hash)) {
            memset(&creds, 0, sizeof(creds));
            return -EIO;
        }

        mutex_lock(&session_mutex);
        user_match = (strncmp(creds.username, param_username, MAX_USERNAME_LEN) == 0);
        hash_match = (crypto_constant_time_compare(input_hash, stored_pw_hash, SHA256_DIGEST_BYTES) == 0);

        if (user_match & hash_match) {
            sess->authenticated = true;
            strncpy(sess->username, creds.username, MAX_USERNAME_LEN - 1);
            sess->username[MAX_USERNAME_LEN - 1] = '\0';
            sess->token_valid = false;
            printk(KERN_INFO "secure_dev: Successful login for user '%s' (PID %d)\n", sess->username, current->pid);
        } else {
            atomic_inc(&failed_login_count);
            printk(KERN_WARNING "secure_dev: Failed login attempt by PID %d\n", current->pid);
            mutex_unlock(&session_mutex);
            memset(&creds, 0, sizeof(creds));
            return -EACCES;
        }
        mutex_unlock(&session_mutex);
        memset(&creds, 0, sizeof(creds));
        return 0;
    }
    case SECURE_IOCTL_LOGOUT:
        mutex_lock(&session_mutex);
        sess->authenticated = false;
        sess->token_valid = false;
        memset(sess->username, 0, MAX_USERNAME_LEN);
        memset(sess->token_hash, 0, SHA256_DIGEST_BYTES);
        mutex_unlock(&session_mutex);
        printk(KERN_INFO "secure_dev: Session logged out for PID %d\n", current->pid);
        return 0;
    case SECURE_IOCTL_STATUS: {
        int status;
        mutex_lock(&session_mutex);
        status = sess->authenticated ? 1 : 0;
        mutex_unlock(&session_mutex);
        if (copy_to_user(argp, &status, sizeof(int))) return -EFAULT;
        return 0;
    }
    case SECURE_IOCTL_GET_TOKEN: {
        unsigned char raw_token[TOKEN_RAW_BYTES];
        char hex[TOKEN_HEX_LEN];
        mutex_lock(&session_mutex);
        if (!sess->authenticated) {
            mutex_unlock(&session_mutex);
            return -EACCES;
        }
        crypto_generate_token(raw_token, TOKEN_RAW_BYTES);
        if (compute_sha256(raw_token, TOKEN_RAW_BYTES, sess->token_hash)) {
            mutex_unlock(&session_mutex);
            memset(raw_token, 0, TOKEN_RAW_BYTES);
            return -EIO;
        }
        sess->token_valid = true;
        mutex_unlock(&session_mutex);
        bytes_to_hex(raw_token, TOKEN_RAW_BYTES, hex);
        memset(raw_token, 0, TOKEN_RAW_BYTES);
        if (copy_to_user(argp, hex, TOKEN_HEX_LEN)) return -EFAULT;
        return 0;
    }
    case SECURE_IOCTL_VERIFY_TOKEN: {
        char user_hex[TOKEN_HEX_LEN];
        unsigned char user_raw[TOKEN_RAW_BYTES];
        unsigned char presented_hash[SHA256_DIGEST_BYTES];
        int verified = 0;

        mutex_lock(&session_mutex);
        if (!sess->token_valid) {
            mutex_unlock(&session_mutex);
            return -EINVAL;
        }
        mutex_unlock(&session_mutex);

        if (copy_from_user(user_hex, argp, TOKEN_HEX_LEN)) return -EFAULT;
        user_hex[TOKEN_HEX_LEN - 1] = '\0';   /* force-terminate untrusted input */

        /* Decode TOKEN_RAW_BYTES (16) bytes, NOT TOKEN_HEX_LEN (33).
         * user_raw is only TOKEN_RAW_BYTES wide — passing the hex length
         * here would write 33 bytes into a 16-byte stack buffer (overflow)
         * and read past the end of user_hex.  Reject malformed hex too. */
        if (hex_to_bytes(user_hex, user_raw, TOKEN_RAW_BYTES))
            return -EINVAL;
        if (compute_sha256(user_raw, TOKEN_RAW_BYTES, presented_hash)) {
            memset(user_raw, 0, TOKEN_RAW_BYTES);
            return -EIO;
        }

        mutex_lock(&session_mutex);
        if (crypto_constant_time_compare(presented_hash, sess->token_hash, SHA256_DIGEST_BYTES) == 0) {
            verified = 1;
        }
        mutex_unlock(&session_mutex);
        memset(user_raw, 0, TOKEN_RAW_BYTES);
        return verified ? 0 : -EACCES;
    }
    default:
        return -ENOTTY;
    }
}

/* ================================================================
 * The file_operations table — wired up to the functions above.
 * core.c references this via `extern const struct file_operations secure_fops;`
 * ================================================================ */
const struct file_operations secure_fops = {
    .owner          = THIS_MODULE,
    .open           = secure_open,
    .release        = secure_release,
    .read           = secure_read,
    .write          = secure_write,
    .unlocked_ioctl = secure_ioctl,
};
