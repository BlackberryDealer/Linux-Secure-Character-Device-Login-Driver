/* ================================================================
 * fops.c — File Operations & User-Kernel Isolation Matrix
 * CSC1107 Project 12 — Secure Character Device Login Driver
 *
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  MEMBER 2 — File Operations & User-Kernel Isolation Matrix   ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  Your Tasks:                                                 ║
 * ║   [TODO]  secure_open()    — alloc session via Member 3      ║
 * ║   [TODO]  secure_release() — free session via Member 3       ║
 * ║   [TODO]  secure_read()    — auth gate + copy_to_user        ║
 * ║   [TODO]  secure_write()   — auth gate + copy_from_user      ║
 * ║   [TODO]  secure_ioctl()   — dispatch LOGIN/LOGOUT/STATUS/   ║
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
 * ================================================================ */
static int secure_open(struct inode *inode, struct file *file)
{
    /* ── STUB: allocate session so other members' code can flow.  Replace. ── */
    struct session_entry *sess = session_alloc();
    if (!sess) {
        printk(KERN_ERR "secure_dev: [STUB] secure_open — session_alloc returned NULL\n");
        return -ENOMEM;
    }
    file->private_data = sess;
    printk(KERN_INFO "secure_dev: [STUB] secure_open by PID %d\n", current->pid);
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
 * ================================================================ */
static int secure_release(struct inode *inode, struct file *file)
{
    /* ── STUB: free session if it exists. ── */
    struct session_entry *sess = file->private_data;
    if (sess) {
        session_free(sess);
        file->private_data = NULL;
    }
    printk(KERN_INFO "secure_dev: [STUB] secure_release by PID %d\n", current->pid);
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
 * ================================================================ */
static ssize_t secure_read(struct file *file, char __user *user_buf,
                            size_t count, loff_t *ppos)
{
    /* ── STUB: lets ALL reads through (no auth check). Replace. ── */
    size_t msg_len = sizeof(kernel_msg) - 1;
    size_t to_copy;

    if (*ppos >= (loff_t)msg_len)
        return 0;
    to_copy = min(count, msg_len - (size_t)*ppos);
    if (copy_to_user(user_buf, kernel_msg + *ppos, to_copy))
        return -EFAULT;
    *ppos += to_copy;
    printk(KERN_INFO "secure_dev: [STUB] secure_read %zu bytes (NO AUTH CHECK)\n", to_copy);
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
 * ================================================================ */
static ssize_t secure_write(struct file *file, const char __user *user_buf,
                             size_t count, loff_t *ppos)
{
    /* ── STUB: accepts ALL writes (no auth check). Replace. ── */
    char tmp[128] = {0};
    size_t copy = min(count, sizeof(tmp) - 1);

    if (copy_from_user(tmp, user_buf, copy))
        return -EFAULT;
    tmp[copy] = '\0';
    printk(KERN_INFO "secure_dev: [STUB] secure_write got \"%s\" (NO AUTH CHECK)\n", tmp);
    return count;
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
 * ================================================================ */
static long secure_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    /* ── STUB: prints command number and returns success. Replace. ── */
    struct session_entry *sess = file->private_data;

    printk(KERN_INFO "secure_dev: [STUB] secure_ioctl cmd=0x%x by PID %d\n",
           cmd, current->pid);

    /* Pretend LOGIN succeeded so user-space stub-testing can proceed */
    if (cmd == SECURE_IOCTL_LOGIN && sess) {
        mutex_lock(&session_mutex);
        sess->authenticated = true;
        strncpy(sess->username, "stub-user", MAX_USERNAME_LEN - 1);
        mutex_unlock(&session_mutex);
        printk(KERN_INFO "secure_dev: [STUB] LOGIN pretended successful\n");
    }
    return 0;
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
