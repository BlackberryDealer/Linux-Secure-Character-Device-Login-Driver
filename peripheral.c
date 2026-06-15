/* ================================================================
 * peripheral.c — Asynchronous Peripheral Event Interceptor
 * CSC1107 Project 12 — Secure Character Device Login Driver
 *
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  MEMBER 5 — Asynchronous Peripheral Event Interceptor        ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  Your Tasks:                                                 ║
 * ║   [TODO]  peripheral_notifier_fn() — the callback the kernel ║
 * ║                                       calls on each netdev   ║
 * ║                                       event                  ║
 * ║   [TODO]  peripheral_register()    — install the notifier    ║
 * ║   [TODO]  peripheral_unregister()  — remove the notifier     ║
 * ║                                                              ║
 * ║  Your "flashy" features for the report:                      ║
 * ║   - Kernel Netdevice Notifier Block: subscribe to async      ║
 * ║     network state changes via register_netdevice_notifier    ║
 * ║   - Hardware State Interception & Purge: catch NETDEV_UP /   ║
 * ║     NETDEV_DOWN events from the RJ45 port and call           ║
 * ║     flush_all_sessions() from session.c — every plug/unplug  ║
 * ║     of the Ethernet cable logs everyone out                  ║
 * ║                                                              ║
 * ║  This directly fulfils the CSC1107 spec requirement about    ║
 * ║  Ethernet cable peripheral detection (Example 2 in the brief)║
 * ╚══════════════════════════════════════════════════════════════╝
 * ================================================================ */

#include "secure_internal.h"

/* Track whether we successfully registered (for safe unregister) */
static bool notifier_registered = false;

/* Track whether the module is ready to handle events. This prevents handling events before the module is fully initialized. */
static atomic_t module_ready = ATOMIC_INIT(0);

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 5 TODO #1:  peripheral_notifier_fn()                 │
 * └──────────────────────────────────────────────────────────────┘
 *
 * The kernel calls this function EVERY time a network interface
 * changes state.  Your job: catch the events that matter (cable
 * plugged in / pulled out) and flush all driver sessions.
 *
 * Function signature is FIXED by the kernel — do not change it.
 *
 * Steps:
 *   1. struct net_device *dev = netdev_notifier_info_to_dev(data);
 *      (Optional — only needed if you want to log the interface name)
 *
 *   2. switch (event) {
 *      case NETDEV_UP:
 *          printk("[PERIPHERAL] %s link UP — flushing sessions",
 *                 dev->name);
 *          flush_all_sessions();
 *          break;
 *      case NETDEV_DOWN:
 *          printk("[PERIPHERAL] %s link DOWN — flushing sessions",
 *                 dev->name);
 *          flush_all_sessions();
 *          break;
 *      default:
 *          // ignore other events (NETDEV_CHANGE, NETDEV_REGISTER, etc.)
 *          break;
 *      }
 *
 *   3. return NOTIFY_DONE;   // tells kernel "we handled it"
 * ================================================================ */
static int peripheral_notifier_fn(struct notifier_block *nb,
                                   unsigned long event, void *data)
{   
    struct net_device *dev;

    /* Check if the module is ready, if not, ignore the event */
    if (atomic_read(&module_ready) == 0)
        return NOTIFY_DONE;

    /* Extract the net_device pointer from the opaque data. */
    dev = netdev_notifier_info_to_dev(data);

    /* Inspect the event type and respond accordingly. */
    switch (event) {
        /* If a network interface is brought up, flush all sessions */
        case NETDEV_UP:
            printk(KERN_WARNING
               "secure_dev: [PERIPHERAL] interface '%s' link UP — "
               "hardware state changed, flushing ALL sessions\n",
               dev->name);
            flush_all_sessions();
            break;
        case NETDEV_DOWN:
        /* If a network interface is taken down */
            printk(KERN_WARNING
               "secure_dev: [PERIPHERAL] interface '%s' link DOWN — "
               "hardware state changed, flushing ALL sessions\n",
               dev->name);
            flush_all_sessions();
            break;
        default:
            // ignore other events (NETDEV_CHANGE, NETDEV_REGISTER, etc.)
            break;
    }

    return NOTIFY_DONE;
}

/* The notifier block — wires our callback into the kernel's network
 * event broadcasting system. */
static struct notifier_block peripheral_nb = {
    .notifier_call = peripheral_notifier_fn,
};


/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 5 TODO #2:  peripheral_register()                    │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Called by core.c during module load.  Registers our callback
 * with the kernel so we receive all network events from now on.
 *
 * Steps:
 *   1. ret = register_netdevice_notifier(&peripheral_nb);
 *   2. If ret != 0: printk error and return ret.
 *   3. notifier_registered = true;
 *   4. printk success and return 0.
 * ================================================================ */
int peripheral_register(void)
{
    int ret = register_netdevice_notifier(&peripheral_nb);

    /* handle registration failure */
    if (ret != 0) {
        printk(KERN_ERR
               "secure_dev: [PERIPHERAL] register_netdevice_notifier "
               "failed (err=%d) — peripheral monitoring NOT active\n",
               ret);
        return ret;
    }

    /* handle registration success */
    notifier_registered = true;

    /* Set module_ready to 1, indicating that the module is fully initialized and ready to handle events. */
    atomic_set(&module_ready, 1);

    printk(KERN_INFO
           "secure_dev: [PERIPHERAL] register_netdevice_notifier "
           "succeeded — peripheral monitoring active\n");

    return 0;
}

/* ================================================================
 * ┌──────────────────────────────────────────────────────────────┐
 * │  MEMBER 5 TODO #3:  peripheral_unregister()                  │
 * └──────────────────────────────────────────────────────────────┘
 *
 * Called by core.c during module unload.  REMOVES our callback so
 * the kernel stops calling us after the module is gone.
 *
 * ⚠ CRITICAL: if you forget this, the kernel will eventually try
 *    to call a function in your module after it has been removed,
 *    causing a kernel panic.  Always unregister symmetrically.
 *
 * Steps:
 *   1. If notifier_registered:
 *        unregister_netdevice_notifier(&peripheral_nb);
 *        notifier_registered = false;
 *   2. printk.
 * ================================================================ */
void peripheral_unregister(void)
{
    /* Only unregister if successfully registered in the first place. */
    if (notifier_registered) {

        /* Set module_ready to 0 to prevent handling events during unregistration */
        atomic_set(&module_ready, 0); 

        /* goes through the notifier list and removes callback */
        unregister_netdevice_notifier(&peripheral_nb);
        notifier_registered = false;
        printk(KERN_INFO "secure_dev: [PERIPHERAL] peripheral_unregister — notifier uninstalled\n");
    }
    /* If the notifier was not registered, print a warning */
    else {
        printk(KERN_WARNING "secure_dev: [PERIPHERAL] peripheral_unregister — notifier was not registered, nothing to uninstall\n");
    }
}
