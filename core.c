/* ================================================================
 * core.c — Subsystem Infrastructure & Sysfs Management
 * CSC1107 Project 12 — Secure Character Device Login Driver
 *
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  MEMBER 1 — Subsystem Infrastructure & Sysfs Management      ║
 * ║  STATUS: IMPLEMENTED                                         ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  Completed work:                                             ║
 * ║   [DONE]  Basic device registration (alloc_chrdev_region,    ║
 * ║          cdev_init, class_create, device_create)             ║
 * ║   [DONE]  Module parameter security (0000 permissions +      ║
 * ║          memset-zero of password after hashing)              ║
 * ║   [DONE]  Kernel version compatibility (#if 6.4 check)       ║
 * ║   [DONE]  failed_logins_show() — sysfs read callback         ║
 * ║   [DONE]  core_sysfs_init()    — sysfs telemetry dashboard   ║
 * ║   [DONE]  core_sysfs_remove()  — sysfs cleanup               ║
 * ║                                                              ║
 * ║  Verify it works after building & loading the module:        ║
 * ║   $ cat /sys/kernel/secure_dev/failed_logins                 ║
 * ║   0                                                          ║
 * ║                                                              ║
 * ║  (The counter will increment once Member 2 implements the    ║
 * ║   real LOGIN ioctl case in fops.c and calls                  ║
 * ║   atomic_inc(&failed_login_count) on failure.)               ║
 * ╚══════════════════════════════════════════════════════════════╝
 * ================================================================ */

#include "secure_internal.h"

/* ── Module metadata ──────────────────────────────────────── */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("CSC1107 Student Group");
MODULE_DESCRIPTION("Secure Character Device Login Driver — Project 12");
MODULE_VERSION("1.0");
MODULE_SOFTDEP("pre: sha256");

/* ── Module parameters (Member 1's "Secure Parameter Isolation" feature) ──
 *
 *   Permissions 0000 means: NOT readable from /sys/module/secure_driver/
 *   parameters/.  A boot-time password set via insmod is therefore not
 *   exposed in /sys after the module loads.  Combined with the password
 *   being zeroed immediately after hashing (in init below), this means
 *   the plaintext credential lives in kernel memory for only a few
 *   microseconds before being scrubbed.
 *
 *   Member 1: This is your "Secure Parameter Isolation" feature.
 *   Explain WHY 0000 permissions matter for security in your report.
 * ──────────────────────────────────────────────────────────────────────── */
char        *param_username = "admin";
static char *param_password = "SecurePass123";
module_param(param_username, charp, 0000);
module_param(param_password, charp, 0000);

/* ── Globals defined here (declared extern in secure_internal.h) ── */
int             major_number;
struct class   *secure_class    = NULL;
struct device  *secure_device   = NULL;
struct cdev     secure_cdev;
struct kobject *secure_kobj     = NULL;
atomic_t        failed_login_count = ATOMIC_INIT(0);

/* ================================================================
 * failed_logins_show() — sysfs read callback (Member 1 implementation)
 *
 * Called automatically by the kernel whenever user-space does:
 *     cat /sys/kernel/secure_dev/failed_logins
 *
 * The kernel hands us a page-sized buffer (PAGE_SIZE = 4 KB) and
 * expects us to write our text representation into it.  We read
 * the atomic counter (which Member 2 increments on every failed
 * login attempt in fops.c) and format it as decimal text.
 *
 * @kobj  — kobject this attribute belongs to (we don't use it)
 * @attr  — kobj_attribute descriptor (we don't use it either)
 * @buf   — destination buffer, at least PAGE_SIZE bytes
 *
 * Returns the number of bytes written (sprintf gives us this).
 * ================================================================ */
static ssize_t failed_logins_show(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   char *buf)
{
    int count = atomic_read(&failed_login_count);
    return sprintf(buf, "%d\n", count);
}

/* sysfs attribute descriptor — links the file name "failed_logins" to
 * the show function above.  __ATTR_RO creates a read-only attribute. */
static struct kobj_attribute failed_logins_attr = __ATTR_RO(failed_logins);

/* ================================================================
 * core_sysfs_init() — Build the sysfs telemetry dashboard
 *                     (Member 1 implementation)
 *
 * Creates:
 *   /sys/kernel/secure_dev/                — directory (kobject)
 *   /sys/kernel/secure_dev/failed_logins   — read-only attribute file
 *
 * After this runs, admins can monitor the driver in real time:
 *     cat /sys/kernel/secure_dev/failed_logins        (one-shot read)
 *     watch -n1 cat /sys/kernel/secure_dev/failed_logins  (live view)
 *
 * Why sysfs and not just dmesg?
 *   • dmesg is a noisy circular log shared by the whole kernel
 *   • sysfs gives admins ONE clean integer they can scrape directly
 *   • Works with monitoring tools (Prometheus exporters, Nagios, etc.)
 *
 * Returns 0 on success, negative errno on failure.
 * ================================================================ */
static int core_sysfs_init(void)
{
    int ret;

    /* Step 1: create the /sys/kernel/secure_dev/ directory.
     * kernel_kobj is a built-in kobject pointing at /sys/kernel/ */
    secure_kobj = kobject_create_and_add("secure_dev", kernel_kobj);
    if (!secure_kobj) {
        printk(KERN_ERR "secure_dev: kobject_create_and_add failed\n");
        return -ENOMEM;
    }

    /* Step 2: add the failed_logins file inside that directory.
     * The kernel will call failed_logins_show() whenever it is read. */
    ret = sysfs_create_file(secure_kobj, &failed_logins_attr.attr);
    if (ret) {
        printk(KERN_ERR "secure_dev: sysfs_create_file failed: %d\n", ret);
        kobject_put(secure_kobj);   /* roll back the kobject from step 1 */
        secure_kobj = NULL;
        return ret;
    }

    printk(KERN_INFO "secure_dev: Sysfs dashboard ready — "
                     "cat /sys/kernel/secure_dev/failed_logins\n");
    return 0;
}

/* ================================================================
 * core_sysfs_remove() — Tear down the sysfs telemetry dashboard
 *                       (Member 1 implementation)
 *
 * Called from secure_driver_exit() during module unload.  Order matters:
 *   1. Remove the file FIRST (sysfs_remove_file)
 *   2. THEN drop the kobject reference (kobject_put)
 * Doing kobject_put first would leave a dangling file.
 *
 * Safe to call even if core_sysfs_init() never ran (the NULL check).
 * ================================================================ */
static void core_sysfs_remove(void)
{
    if (secure_kobj) {
        sysfs_remove_file(secure_kobj, &failed_logins_attr.attr);
        kobject_put(secure_kobj);
        secure_kobj = NULL;
        printk(KERN_INFO "secure_dev: Sysfs dashboard removed\n");
    }
}

/* ================================================================
 * secure_driver_init() — Module Load (insmod)
 *
 * ★ This function is COMPLETE and WORKING from Day 1 so that other
 *   members can test their stubs as soon as the repo is cloned.
 *
 *   Member 1: you should still UNDERSTAND every line below for your
 *   report.  Feel free to enhance with extra error handling or logging.
 * ================================================================ */
static int __init secure_driver_init(void)
{
    dev_t dev_num;
    int   ret;

    printk(KERN_INFO "secure_dev: ============================================\n");
    printk(KERN_INFO "secure_dev: Loading Secure Character Device Login Driver\n");
    printk(KERN_INFO "secure_dev: ============================================\n");

    /* Step 1: hash admin password via Member 4's compute_sha256 */
    ret = compute_sha256((unsigned char *)param_password,
                         strlen(param_password), stored_pw_hash);
    if (ret) {
        printk(KERN_ERR "secure_dev: compute_sha256 failed: %d\n", ret);
        return ret;
    }
    /* Wipe plaintext password from memory — Secure Parameter Isolation */
    memset(param_password, 0, strlen(param_password));

    /* Step 2: allocate dynamic device major number */
    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ERR "secure_dev: alloc_chrdev_region failed: %d\n", ret);
        return ret;
    }
    major_number = MAJOR(dev_num);

    /* Step 3: register the cdev with the file_operations from fops.c */
    cdev_init(&secure_cdev, &secure_fops);
    secure_cdev.owner = THIS_MODULE;
    ret = cdev_add(&secure_cdev, dev_num, 1);
    if (ret < 0) {
        printk(KERN_ERR "secure_dev: cdev_add failed: %d\n", ret);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    /* Step 4: create device class (API differs between kernel versions) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    secure_class = class_create(CLASS_NAME);
#else
    secure_class = class_create(THIS_MODULE, CLASS_NAME);
#endif
    if (IS_ERR(secure_class)) {
        cdev_del(&secure_cdev);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(secure_class);
    }

    /* Step 5: create the /dev/secure_dev node via udev */
    secure_device = device_create(secure_class, NULL, dev_num,
                                   NULL, DEVICE_NAME);
    if (IS_ERR(secure_device)) {
        class_destroy(secure_class);
        cdev_del(&secure_cdev);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(secure_device);
    }

    /* Step 6: Member 1's sysfs telemetry dashboard */
    ret = core_sysfs_init();
    if (ret) {
        device_destroy(secure_class, dev_num);
        class_destroy(secure_class);
        cdev_del(&secure_cdev);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    /* Step 7: Member 3's session subsystem */
    ret = session_subsystem_init();
    if (ret) {
        core_sysfs_remove();
        device_destroy(secure_class, dev_num);
        class_destroy(secure_class);
        cdev_del(&secure_cdev);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    /* Step 8: Member 5's peripheral notifier */
    ret = peripheral_register();
    if (ret) {
        session_subsystem_cleanup();
        core_sysfs_remove();
        device_destroy(secure_class, dev_num);
        class_destroy(secure_class);
        cdev_del(&secure_cdev);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    printk(KERN_INFO "secure_dev: /dev/%s ready — major %d\n",
           DEVICE_NAME, major_number);
    printk(KERN_INFO "secure_dev: Module loaded successfully\n");
    return 0;
}

/* ================================================================
 * secure_driver_exit() — Module Unload (rmmod)
 * Tears everything down in REVERSE order of init.
 * ================================================================ */
static void __exit secure_driver_exit(void)
{
    dev_t dev_num = MKDEV(major_number, 0);

    peripheral_unregister();          /* Member 5 */
    session_subsystem_cleanup();      /* Member 3 */
    core_sysfs_remove();              /* Member 1 */

    device_destroy(secure_class, dev_num);
    class_destroy(secure_class);
    cdev_del(&secure_cdev);
    unregister_chrdev_region(dev_num, 1);

    /* Security: zero sensitive data before unloading */
    memset(stored_pw_hash, 0, sizeof(stored_pw_hash));

    printk(KERN_INFO "secure_dev: Module unloaded\n");
}

module_init(secure_driver_init);
module_exit(secure_driver_exit);
