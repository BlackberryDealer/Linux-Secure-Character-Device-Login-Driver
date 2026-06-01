/* ================================================================
 * secure_internal.h — The Locked Integration Contract
 * CSC1107 Project 12 — Secure Character Device Login Driver
 *
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  ⚠ DO NOT MODIFY THIS FILE WITHOUT TEAM AGREEMENT  ⚠       ║
 * ║                                                              ║
 * ║  This header is the contract between all 5 members. Every    ║
 * ║  function signature and global variable type is defined      ║
 * ║  here. If you change a function signature in your .c file    ║
 * ║  to differ from what is declared here, the build will fail.  ║
 * ║                                                              ║
 * ║  This is INTENTIONAL — it forces clean integration.          ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Included by all 5 kernel .c files: core.c, fops.c, session.c,
 * crypto.c, peripheral.c.  NEVER included by user_app.c.
 * ================================================================ */

#ifndef SECURE_INTERNAL_H
#define SECURE_INTERNAL_H

/* ── All kernel #includes in one place ────────────────────── */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/list.h>          /* list_head, list_add, list_del               */
#include <linux/atomic.h>        /* atomic_t, atomic_inc, atomic_read           */
#include <linux/kobject.h>       /* kobject_create_and_add (Member 1 sysfs)     */
#include <linux/sysfs.h>         /* sysfs_create_file, __ATTR_RO                */
#include <linux/notifier.h>      /* notifier_block (Member 5 peripheral)        */
#include <linux/netdevice.h>     /* register_netdevice_notifier, NETDEV_UP/DOWN */
#include <crypto/hash.h>         /* crypto_alloc_shash, crypto_shash_update     */
#include <crypto/algapi.h>       /* crypto_memneq — constant-time compare       */

/* User/kernel shared definitions (ioctl numbers, structs) */
#include "secure_driver.h"

/* ================================================================
 * struct session_entry — Per-Open-File Session Record
 *
 * Allocated by Member 3's session_alloc() and attached to
 * file->private_data.  Members 2 and 4 access these fields
 * directly while holding session_mutex.
 *
 * The node field links each session into the global session_list
 * so that Member 5's peripheral.c can iterate them when an
 * Ethernet event triggers a flush.
 * ================================================================ */
struct session_entry {
    bool             authenticated;
    char             username[MAX_USERNAME_LEN];
    bool             token_valid;
    unsigned char    token_hash[SHA256_DIGEST_BYTES];
    pid_t            pid;                  /* for log messages only             */
    struct list_head node;                 /* links into session_list           */
};

/* ================================================================
 * Global Variables — DECLARATIONS only
 * Each variable is DEFINED in exactly one .c file (extern here).
 * ================================================================ */

/* Defined in core.c (Member 1) */
extern int             major_number;
extern struct class   *secure_class;
extern struct device  *secure_device;
extern struct cdev     secure_cdev;
extern struct kobject *secure_kobj;
extern atomic_t        failed_login_count;
extern char           *param_username;

/* Defined in crypto.c (Member 4) */
extern unsigned char   stored_pw_hash[SHA256_DIGEST_BYTES];

/* Defined in session.c (Member 3) */
extern struct mutex      session_mutex;
extern struct list_head  session_list;

/* Defined in fops.c (Member 2) */
extern const struct file_operations secure_fops;

/* ================================================================
 * Function Prototypes — LOCKED SIGNATURES
 * Implement these exactly as declared in your .c file.
 * ================================================================ */

/* ── session.c (Member 3) ────────────────────────────────── */
int                    session_subsystem_init(void);
void                   session_subsystem_cleanup(void);
struct session_entry  *session_alloc(void);
void                   session_free(struct session_entry *sess);
void                   flush_all_sessions(void);

/* ── crypto.c (Member 4) ─────────────────────────────────── */
int  compute_sha256(const unsigned char *data, size_t data_len,
                    unsigned char *digest);
int  crypto_constant_time_compare(const void *a, const void *b, size_t len);
void crypto_generate_token(unsigned char *out, size_t len);
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex);
int  hex_to_bytes(const char *hex, unsigned char *bytes, size_t len);

/* ── peripheral.c (Member 5) ─────────────────────────────── */
int  peripheral_register(void);
void peripheral_unregister(void);

#endif /* SECURE_INTERNAL_H */
