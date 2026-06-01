/* ================================================================
 * secure_driver.h — Shared User/Kernel Header
 * CSC1107 Project 12 — Secure Character Device Login Driver
 *
 * Included by BOTH:
 *   - All kernel .c files (via secure_internal.h)
 *   - user_app.c (user-space test application)
 *
 * Defines the ioctl command numbers and data structures used
 * to communicate between user space and the kernel module.
 *
 * **THIS FILE IS LOCKED.** Nobody on the team modifies it after
 * Day 1 — it is the contract that the user-space app depends on.
 * ================================================================ */

#ifndef SECURE_DRIVER_H
#define SECURE_DRIVER_H

#ifdef __KERNEL__
    #include <linux/ioctl.h>
    #include <linux/types.h>
#else
    #include <sys/ioctl.h>
#endif

/* ── Device identification ────────────────────────────────── */
#define DEVICE_NAME         "secure_dev"
#define CLASS_NAME          "secure_class"

/* ── Buffer & string limits ───────────────────────────────── */
#define MAX_BUFFER_SIZE     1024
#define MAX_USERNAME_LEN    32
#define MAX_PASSWORD_LEN    64

/* ── Cryptographic constants ──────────────────────────────── */
#define SHA256_DIGEST_BYTES 32
#define TOKEN_RAW_BYTES     16
#define TOKEN_HEX_LEN       (TOKEN_RAW_BYTES * 2 + 1)

/* ── ioctl command numbers (magic = 'K') ──────────────────── */
#define SECURE_IOCTL_MAGIC          'K'
#define SECURE_IOCTL_LOGIN          _IOW(SECURE_IOCTL_MAGIC, 1, struct login_data)
#define SECURE_IOCTL_LOGOUT         _IO (SECURE_IOCTL_MAGIC, 2)
#define SECURE_IOCTL_STATUS         _IOR(SECURE_IOCTL_MAGIC, 3, int)
#define SECURE_IOCTL_GET_TOKEN      _IOR(SECURE_IOCTL_MAGIC, 4, struct token_data)
#define SECURE_IOCTL_VERIFY_TOKEN   _IOW(SECURE_IOCTL_MAGIC, 5, struct token_data)

/* ── Shared data structures ───────────────────────────────── */
struct login_data {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
};

struct token_data {
    char token[TOKEN_HEX_LEN];
};

#endif /* SECURE_DRIVER_H */
