/* ================================================================
 * peripheral.c - Asynchronous Peripheral Event Interceptor
 * CSC1107 Project 12 - Secure Character Device Login Driver
 *
 * Registers a netdevice notifier so the driver reacts to network
 * interface state changes. When a link goes up or down (for example an
 * Ethernet cable plugged into or pulled from the RJ45 port) it calls
 * flush_all_sessions(), forcing every open session back to the logged-
 * out state. This is the project's peripheral-detection requirement:
 * a hardware event drives a security action.
 * ================================================================ */

#include "secure_internal.h"

/* Track whether we successfully registered (for safe unregister) */
static bool notifier_registered = false;

/* Track whether the module is ready to handle events. This prevents handling events before the module is fully initialized. */
static atomic_t module_ready = ATOMIC_INIT(0);

/* ================================================================
 * peripheral_notifier_fn() - kernel callback for every netdev event.
 *
 * The signature is fixed by the kernel. The module_ready guard makes us
 * ignore the events the kernel replays while we are still registering.
 * We act only on NETDEV_UP and NETDEV_DOWN, flushing all sessions on
 * either, and ignore every other event. Always returns NOTIFY_DONE so
 * the rest of the notifier chain still runs.
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
 * peripheral_register() - install the netdevice notifier.
 *
 * Called by core.c during module load. On success it records that the
 * notifier is registered and sets module_ready so later events are
 * handled. Returns 0 on success, or the error from
 * register_netdevice_notifier() on failure.
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
 * peripheral_unregister() - remove the netdevice notifier.
 *
 * Called by core.c during module unload. Clearing module_ready first,
 * then unregistering, ensures no callback runs against a module that is
 * going away. Skipping this would let the kernel call into freed module
 * code and panic, so registration and unregistration stay symmetric.
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
