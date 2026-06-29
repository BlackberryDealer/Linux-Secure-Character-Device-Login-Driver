/* ================================================================
 * session.c - State Machine and Concurrent Kernel Locking Engine
 * CSC1107 Project 12 - Secure Character Device Login Driver
 * Owner: Member 3
 *
 * Owns the lifecycle and locking of session records. Each session is
 * allocated on demand when a process opens /dev/secure_dev (not from a
 * fixed array), attached to file->private_data, and linked into a
 * global list so a peripheral event can flush them all at once. One
 * mutex serialises every change to that list and to session fields.
 *
 * ── CONCURRENCY MODEL (read this before touching the locking) ──
 *
 *   ONE global lock, `session_mutex`, protects TWO things:
 *     1. The integrity of the `session_list` linked list itself
 *        (add/remove must be serialized).
 *     2. The mutable fields of every session_entry on that list
 *        (authenticated / token_valid / username / token_hash).
 *
 *   fops.c takes the SAME mutex when it reads/writes those session
 *   fields, so all of {open, read, write, ioctl, release} and our
 *   flush_all_sessions() are serialized against each other. No file
 *   in this project ever nests another lock inside session_mutex,
 *   so there is no lock-ordering / deadlock hazard.
 *
 *   We never call copy_*_user(), kmalloc(GFP_KERNEL) blocking work,
 *   or any sleeping primitive WHILE HOLDING the lock for longer than
 *   necessary — kmalloc in session_alloc() happens BEFORE we take the
 *   lock, and kfree in session_free() happens AFTER we release it.
 * ================================================================ */

#include "secure_internal.h"

/* ── Globals defined here (declared extern in secure_internal.h) ── */
struct mutex     session_mutex;
LIST_HEAD(session_list);   /* global list of all active sessions */

/* ================================================================
 * session_subsystem_init()
 *
 * Called once by core.c during module load (before any file can be
 * opened, so no locking is required here).
 *
 *   1. mutex_init(&session_mutex) — REQUIRED: session_mutex is a
 *      plain `struct mutex` (not DEFINE_MUTEX), so it is NOT
 *      statically initialised. Skipping this would mean fops.c locks
 *      an uninitialised mutex → undefined behaviour.
 *   2. INIT_LIST_HEAD(&session_list) — defensive; LIST_HEAD() above
 *      already initialises it, but being explicit documents intent.
 * ================================================================ */
int session_subsystem_init(void)
{
    mutex_init(&session_mutex);
    INIT_LIST_HEAD(&session_list);
    printk(KERN_INFO "secure_dev: session subsystem initialised\n");
    return 0;
}

/* ================================================================
 * session_subsystem_cleanup()
 *
 * Called once by core.c during module unload (rmmod). Defensive
 * sweep: if any session_entry is somehow still on the list, free it
 * so the module leaves no leaked slab memory behind.
 *
 * In normal operation the list is already empty here — the kernel
 * refuses to rmmod while any fd is open (cdev owner refcount), and
 * every close() runs session_free(). This loop only matters as a
 * safety net, but a "secure" driver should never leak kernel memory.
 *
 * We use list_for_each_entry_safe() because we kfree the node we are
 * standing on during iteration; the _safe variant caches the next
 * pointer first so the walk does not dereference freed memory.
 * ================================================================ */
void session_subsystem_cleanup(void)
{
    struct session_entry *sess, *tmp;
    int leaked = 0;

    mutex_lock(&session_mutex);
    list_for_each_entry_safe(sess, tmp, &session_list, node) {
        list_del(&sess->node);
        /* Wipe any residual credentials before returning memory to slab */
        memset(sess, 0, sizeof(*sess));
        kfree(sess);
        leaked++;
    }
    mutex_unlock(&session_mutex);

    if (leaked)
        printk(KERN_WARNING
               "secure_dev: session cleanup freed %d leftover session(s)\n",
               leaked);
    else
        printk(KERN_INFO "secure_dev: session subsystem cleaned up\n");
}

/* ================================================================
 * session_alloc()
 *
 * Called by Member 2's secure_open() when a new process opens
 * /dev/secure_dev. This is the "Dynamic Context Memory Binding"
 * feature — one descriptor allocated on demand from the kernel slab,
 * then linked into the global list so flush_all_sessions() can find it.
 *
 *   1. kmalloc the descriptor (done OUTSIDE the lock — GFP_KERNEL may
 *      sleep, and we want to hold session_mutex for as short a window
 *      as possible).
 *   2. Zero it so authenticated/token_valid start false and no stale
 *      slab contents leak into a fresh session.
 *   3. Record the owning PID (for log messages only) and init the
 *      list node.
 *   4. Take the lock JUST to splice the node onto session_list.
 *
 * Returns the session pointer, or NULL on allocation failure (which
 * secure_open() translates into -ENOMEM to user space).
 * ================================================================ */
struct session_entry *session_alloc(void)
{
    struct session_entry *sess;

    sess = kmalloc(sizeof(*sess), GFP_KERNEL);
    if (!sess) {
        printk(KERN_ERR "secure_dev: session_alloc — kmalloc failed\n");
        return NULL;
    }

    memset(sess, 0, sizeof(*sess));
    sess->pid           = current->pid;
    sess->authenticated = false;
    sess->token_valid   = false;
    INIT_LIST_HEAD(&sess->node);

    /* Publish the new session to the global list (serialised). */
    mutex_lock(&session_mutex);
    list_add(&sess->node, &session_list);
    mutex_unlock(&session_mutex);

    printk(KERN_INFO "secure_dev: session allocated for PID %d\n", sess->pid);
    return sess;
}

/* ================================================================
 * session_free()
 *
 * Called by Member 2's secure_release() when a process closes the
 * device. Removes the session from the global list, scrubs its
 * secrets, and returns the memory to the slab allocator.
 *
 *   1. NULL guard (open may have failed before a session existed).
 *   2. list_del UNDER the lock — once unlinked, flush_all_sessions()
 *      can no longer reach this node, which is what makes the kfree
 *      below safe against a concurrent flush.
 *   3. memset(0) AFTER unlinking, BEFORE kfree — "Immediate
 *      Destructive Sanitization": no leftover username / token hash
 *      survives in freed kernel memory.
 *   4. kfree outside the lock (kfree must not be needlessly held under
 *      a mutex, and the node is already private to us at this point).
 * ================================================================ */
void session_free(struct session_entry *sess)
{
    pid_t pid;

    if (!sess)
        return;

    pid = sess->pid;

    mutex_lock(&session_mutex);
    list_del(&sess->node);
    mutex_unlock(&session_mutex);

    /* Scrub credentials/token before the memory can be reused. */
    memset(sess, 0, sizeof(*sess));
    kfree(sess);

    printk(KERN_INFO "secure_dev: session freed for PID %d\n", pid);
}

/* ================================================================
 * flush_all_sessions()
 *
 * Called by Member 5's peripheral.c when an Ethernet link change
 * (NETDEV_UP / NETDEV_DOWN) is detected. Forcibly de-authenticates
 * EVERY active session — a hardware-triggered, system-wide logout.
 *
 * We walk the list under the lock and clear the auth state in place.
 * We do NOT free or unlink anything here: the file descriptors are
 * still open, so the session_entry structs must stay alive. We only
 * reset them to the unauthenticated state, exactly as a LOGOUT ioctl
 * would, so the next read/write from those fds is rejected until the
 * user logs in again.
 *
 * list_for_each_entry() (non-safe) is correct here because we never
 * remove a node inside the loop.
 *
 * Locking note: this runs from the netdevice notifier, which the
 * kernel invokes in process context (under RTNL). Sleeping locks like
 * mutex_lock() are therefore permitted. The lock order is always
 * RTNL → session_mutex and never the reverse, so no deadlock arises.
 * ================================================================ */
void flush_all_sessions(void)
{
    struct session_entry *sess;
    int flushed = 0;

    mutex_lock(&session_mutex);
    list_for_each_entry(sess, &session_list, node) {
        if (sess->authenticated) {
            printk(KERN_WARNING
                   "secure_dev: flushing authenticated session (PID %d)\n",
                   sess->pid);
            sess->authenticated = false;
            sess->token_valid   = false;
            memset(sess->username,   0, MAX_USERNAME_LEN);
            memset(sess->token_hash, 0, SHA256_DIGEST_BYTES);
            flushed++;
        }
    }
    mutex_unlock(&session_mutex);

    printk(KERN_INFO
           "secure_dev: flush_all_sessions complete — %d session(s) logged out\n",
           flushed);
}
