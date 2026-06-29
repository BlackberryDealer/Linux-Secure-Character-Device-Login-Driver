/* ================================================================
 * fops.c - File Operations and User-Kernel Isolation Matrix
 * CSC1107 Project 12 - Secure Character Device Login Driver
 * Owner: Member 2
 *
 * Implements the device file_operations: open, release, read, write
 * and ioctl. read and write sit behind a strict security gate that
 * rejects and logs any access from an unauthenticated session. Every
 * user transfer goes through a bounded min() plus copy_*_user(), so
 * user space can never reach past the intended buffer. ioctl is the
 * control plane for login, logout, status and the token challenge.
 *
 * Calls into: session.c (session fields), crypto.c (hashing, compare,
 * token, hex) and core.c (failed_login_count).
 * ================================================================ */

#include "secure_internal.h"

/* Fixed message returned to authenticated reads */
static const char kernel_msg[] = "Hello World from the kernel space\n";

/* ================================================================
 * secure_open() - called when a process opens /dev/secure_dev.
 *
 * Allocates a fresh session and binds it to this open file via
 * file->private_data. Tying auth state to the open file (rather than a
 * global PID map) keeps sessions isolated, and every new open starts
 * unauthenticated. Returns -ENOMEM if the session cannot be allocated.
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
 * secure_release() - called when a process closes the device.
 *
 * Frees the session via session_free() (which scrubs its credentials
 * and token before returning the memory) and clears private_data to
 * avoid a dangling pointer. The NULL guard covers an open that failed
 * before a session existed.
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
 * secure_read() - hand the kernel message to an authenticated reader.
 *
 * The security gate: the read is rejected with -EACCES and logged as a
 * [SECURITY ALERT] unless the session is authenticated. Past the gate
 * it serves "Hello World from the kernel space", using *ppos for EOF
 * and min() with copy_to_user() so a user buffer can never pull more
 * than the message length out of kernel memory.
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
 * secure_write() - accept a message from an authenticated writer.
 *
 * Same security gate as secure_read(). The username is copied out of
 * the session under the lock, then the lock is released before the
 * copy_from_user() and printk so no slow work runs while holding it.
 * The length is bounded with min() and the buffer is force-terminated,
 * so over-long or unterminated input cannot overflow. Returns the
 * number of bytes accepted, or -EACCES / -EFAULT.
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
 * secure_ioctl() - control plane: dispatch the five auth commands.
 *
 * Each case takes session_mutex while touching session fields.
 *   LOGIN        Hash the supplied password, compare username and hash,
 *                and combine the two results with a bitwise & (not &&)
 *                so the check cannot short-circuit and leak timing. The
 *                plaintext is wiped on every exit path.
 *   LOGOUT       Clear the auth flag and wipe the username and token.
 *   STATUS       Report whether this session is authenticated.
 *   GET_TOKEN    Require auth, issue a random token, store only its
 *                SHA-256 hash, and return the token as hex.
 *   VERIFY_TOKEN Re-hash the token the user sends back and compare it,
 *                in constant time, against the stored hash.
 * Returns 0 on success or a negative errno (-EACCES, -EINVAL, -EFAULT,
 * -EIO, -ENOTTY) depending on the case.
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
