/* ================================================================
 * core.c - Subsystem Infrastructure and Sysfs Management
 * CSC1107 Project 12 - Secure Character Device Login Driver
 *
 * Brings the driver up and tears it down:
 *   - Registers the char device (region, cdev, class, /dev node).
 *   - Hashes the admin password at load and wipes the plaintext.
 *   - Publishes a read-only failed-login counter on sysfs at
 *     /sys/kernel/secure_dev/failed_logins.
 *   - Starts the sysfs, session and peripheral subsystems in order
 *     and rolls each one back on failure.
 * ================================================================ */

#include "secure_internal.h"

/* ── Module metadata ──────────────────────────────────────── */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("CSC1107 Student Group");
MODULE_DESCRIPTION("Secure Character Device Login Driver — Project 12");
MODULE_VERSION("1.0");
MODULE_SOFTDEP("pre: sha256");

/* ── Module parameters ────────────────────────────────────────────
 * The 0000 permission keeps these out of /sys/module/secure_driver/
 * parameters/, so a password passed via insmod is never exposed there.
 * The plaintext is also zeroed right after hashing (see init below), so
 * it only lives in kernel memory briefly.
 * ──────────────────────────────────────────────────────────────── */
char        *param_username = "admin";
static char param_password[128] = "SecurePass123";
module_param(param_username, charp, 0000);
module_param_string(param_password, param_password, sizeof(param_password), 0000);

/* ── Globals defined here (declared extern in secure_internal.h) ── */
int             major_number;
struct class   *secure_class    = NULL;
struct device  *secure_device   = NULL;
struct cdev     secure_cdev;
struct kobject *secure_kobj     = NULL;
atomic_t        failed_login_count = ATOMIC_INIT(0);

/* ================================================================
 * failed_logins_show() - sysfs read callback.
 *
 * Runs when user space reads /sys/kernel/secure_dev/failed_logins.
 * Formats the atomic failed-login counter (incremented by fops.c on
 * each rejected login) into the kernel-supplied buffer and returns
 * the number of bytes written.
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
 * core_sysfs_init() - build the sysfs monitoring node.
 *
 * Creates the /sys/kernel/secure_dev/ directory and the read-only
 * failed_logins file inside it, giving admins one clean integer to
 * scrape instead of grepping dmesg. Rolls back the kobject if the
 * file cannot be created. Returns 0 on success, negative errno on
 * failure.
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
 * core_sysfs_remove() - tear down the sysfs node.
 *
 * Removes the file before dropping the kobject reference (the reverse
 * order would leave a dangling file). The NULL check makes it safe to
 * call even if core_sysfs_init() never ran.
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
 * secure_driver_init() - module load (insmod).
 *
 * Eight ordered steps: hash and wipe the password, register the char
 * device region, cdev, class and /dev node, then start the sysfs,
 * session and peripheral subsystems. Every step that can fail rolls
 * back the earlier ones in reverse, so a failed load leaves nothing
 * registered. Returns 0 on success, negative errno on failure.
 * ================================================================ */
static int __init secure_driver_init(void)
{
    dev_t dev_num;
    int   ret;

    printk(KERN_INFO "secure_dev: ============================================\n");
    printk(KERN_INFO "secure_dev: Loading Secure Character Device Login Driver\n");
    printk(KERN_INFO "secure_dev: ============================================\n");

    /* Step 1: hash the admin password, then wipe the plaintext.
     * The wipe runs on the failure path too, so the plaintext never
     * lingers in kernel memory even if hashing fails. */
    ret = compute_sha256((unsigned char *)param_password,
                         strlen(param_password), stored_pw_hash);
    if (ret) {
        printk(KERN_ERR "secure_dev: compute_sha256 failed: %d\n", ret);
        memset(param_password, 0, strlen(param_password));
        return ret;
    }
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

    /* Step 6: this file's sysfs telemetry dashboard (core_sysfs_init above) */
    ret = core_sysfs_init();
    if (ret) {
        device_destroy(secure_class, dev_num);
        class_destroy(secure_class);
        cdev_del(&secure_cdev);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    /* Step 7: start the session subsystem (session.c) */
    ret = session_subsystem_init();
    if (ret) {
        core_sysfs_remove();
        device_destroy(secure_class, dev_num);
        class_destroy(secure_class);
        cdev_del(&secure_cdev);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    /* Step 8: register the peripheral notifier (peripheral.c) */
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

    peripheral_unregister();          /* peripheral.c */
    session_subsystem_cleanup();      /* session.c */
    core_sysfs_remove();              /* this file's sysfs dashboard */

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
