# Project 12: Secure Character Device Login Driver

### CSC1107 Operating Systems — Modular Loadable Kernel Module (LKM)

**Target Platform:** Raspberry Pi 4 Model B (aarch64) · Raspberry Pi OS 64-bit

---

## 📌 Project Overview

This project implements a secure, loadable Linux character device driver (`/dev/secure_dev`) featuring multi-process session tracking, a custom Sysfs telemetry dashboard, side-channel attack mitigations, and an asynchronous hardware-link interceptor.

The architecture is highly decoupled, distributing specialized kernel workloads across **5 separate C source files** that compile independently and link dynamically into a single, cohesive kernel object (`secure_driver.ko`).

---

## 🚀 Quick Start: Automated Execution & Testing

The workspace comes out-of-the-box as a fully compiling skeleton framework using structural "stubs" (placeholders). You can execute the entire compilation, installation, deployment, and testing lifecycle in a single command using the master automation script.

### Prerequisites

Ensure your Raspberry Pi has up-to-date kernel compilation headers and building facilities installed:

```bash
sudo apt update
sudo apt install raspberrypi-kernel-headers build-essential
```

### Running the End-to-End Automation Script

Execute the master utility script with root privileges:

```bash
sudo bash run.sh
```

### What `run.sh` Automates Under the Hood

- Performs environment pre-flight checks (root privileges, build tools, headers).
- Triggers the build system to compile the driver components and user-space program.
- Cleanly unloads any previous instances of the driver (`rmmod`).
- Injects the newly compiled module into the kernel space (`insmod`).
- Verifies and sets accessible permissions (`0666`) for the automatically generated `/dev/secure_dev` node.
- Displays the initial kernel ring logs (`dmesg`).
- Executes the automated user-space validation harness (`./user_app --demo`).
- Prints out post-execution security telemetry logs straight from the kernel buffer.

Optional: Configure custom driver verification credentials at boot time using module parameters:

```bash
sudo bash run.sh --username administrator --password SecurePassword2026!
```

---

## 📂 Repository Directory Tree & File Responsibilities

```text
├── Makefile                # Master build system manager
├── run.sh                  # Comprehensive end-to-end automation test script
├── secure_driver.h         # LOCKED: User-Space / Kernel Interface Contract
├── secure_internal.h       # LOCKED: Subsystem Inter-Module Linkage Contract
├── user_app.c              # User-space test application (Interactive / Automated)
│
├── core.c                  # Subsystem Infrastructure & Sysfs Management
├── fops.c                  # Virtual File System (VFS) Interfaces & Security Isolation
├── session.c               # State Machine & Concurrent Lock Engine
├── crypto.c                # Cryptographic Subsystem & Side-Channel Shielding
└── peripheral.c            # Asynchronous Peripheral Link Interceptor
```

---

## 🛠️ Detailed File Architecture & Component Roles

### 🧱 Build & Interface Infrastructure

#### Makefile

Manages the compilation targets. It hooks directly into the running kernel's kbuild engine (`/lib/modules/$(shell uname -r)/build`) to compile and structurally link the 5 distinct source components into `secure_driver.ko`. It also compiles the accompanying user-space executable.

#### secure_driver.h

The User/Kernel Contract. This shared header is included by both the driver files and the user-space application. It strictly maps data structures like `struct login_data` and `struct token_data`, alongside the core IOCTL definitions and buffer size constraints.

#### secure_internal.h

The Kernel Subsystem Contract. This header coordinates internal global linkages between the driver modules. It declares global variables (such as the `session_mutex` and `session_list`) and anchors the shared function prototypes to enforce strict build compatibility.

### ⚙️ Kernel Space Source Files

#### core.c (Subsystem Infrastructure)

Responsible for the absolute lifecycle handling of the driver (`module_init` and `module_exit`). It automatically provisions major numbers, creates device class segments, and instantiates the hotplug device node under `/dev/secure_dev`. Additionally, it builds the custom administration dashboard inside Sysfs at `/sys/kernel/secure_dev/failed_logins`.

#### fops.c (File Operations Router)

Acts as the entry gateway from the Linux Virtual File System (VFS), mapping user-layer actions into kernel contexts (`open`, `release`, `read`, `write`, and `ioctl`). It enforces strict security access authorization gates before allowing read/write operations and guards against buffer overruns using `copy_to_user` and `copy_from_user` boundary checks.

#### session.c (State Machine Engine)

Manages multi-tenant process tracking. Instead of relying on vulnerable static arrays, it dynamically allocates a descriptor node on-demand (`kmalloc`) when a process accesses the device node, mapping tracking metrics to `file->private_data`. State adjustments are synchronized across concurrent application threads using kernel mutex lock primitives.

#### crypto.c (Cryptographic Subsystem)

Leverages native synchronous hash cipher interfaces (`crypto_alloc_shash`) to validate password metrics and generate session validation tokens completely inside kernel space. It hardens authentication evaluations by replacing standard comparisons with constant-time verification wrappers (`crypto_memneq`) to defend against side-channel timing attacks.

#### peripheral.c (Peripheral Interceptor)

Handles raw system asynchronous dependencies. It registers a low-level notifier component (`register_netdevice_notifier`) with the Linux link-layer network engine. The moment a network link change occurs on the hardware (e.g., an Ethernet link transitioning up/down), it intercepts the event and triggers a system-wide reset, immediately wiping out active driver credentials.

---

## 🔬 Practical Multi-Mode Diagnostics Testing

Beyond the automated script, you can execute individual parts manually to conduct precision system testing.

### 1. Granular Compilation Options

```bash
# Build the driver module and user binary
make

# Build only the kernel driver object
make module

# Build only the user testing application
make user_app

# Purge object artifacts and compiled binaries safely
make clean
```

### 2. Interactive Terminal Testing (`user_app.c`)

While `run.sh` fires the tool using the headless `--demo` automation parameter, running the executable directly drops you into a step-by-step diagnostic control deck:

```bash
./user_app
```

#### Available Manual Operations

- Open Device Node
- Close Device Node
- Authenticate (LOGIN)
- Read from Device
- Check Active Status
- Request Verification Token
- Submit Token for Validation
- Graceful Session Logout
- Bad Login Test (Option 10)

### 3. Monitoring System Telemetry Output

Keep a dedicated terminal window running to monitor real-time security alerts, print statements, and internal lifecycle updates directly from the kernel ring logs:

```bash
# View compiled driver log strings
dmesg | grep secure_dev

# Continuous real-time tail monitoring of the driver logs
dmesg -w | grep secure_dev
```

---

## 💡 Pro-Tip for Git Contributions

- **Do NOT edit `secure_driver.h` or `secure_internal.h`**: These headers form a hard cross-file compiler contract. Modifying function parameters or declarations in these files will disrupt integration across the other code files.
- **Incremental Replacement**: Each source file contains standard `[TODO]` markers. Replace the `/* ── STUB ── */` log markers only when your true functional operations are thoroughly validated.
