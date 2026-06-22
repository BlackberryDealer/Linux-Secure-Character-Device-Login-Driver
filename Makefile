# ================================================================
# Makefile — Secure Character Device Login Driver
# CSC1107 Operating Systems — Project 12
#
# Builds:
#   secure_driver.ko  — kernel module (5 .c files linked together)
#   user_app          — user-space test application
#
# File ownership:
#   core.c        → Member 1 (Subsystem Infrastructure & Sysfs)
#   fops.c        → Member 2 (File Operations & Isolation Matrix)
#   session.c     → Member 3 (State Machine & Locking Engine)
#   crypto.c      → Member 4 (Cryptographic Subsystem)
#   peripheral.c  → Member 5 (Peripheral Event Interceptor)
#   secure_internal.h → LOCKED contract (do not modify)
#   secure_driver.h   → LOCKED contract shared with user_app
#   user_app.c    → shared test program
#   run.sh        → shared automation script
#   Makefile      → shared build infrastructure
#
# Usage:
#   make              build everything
#   make module       build only the kernel module
#   make user_app     build only the user-space app
#   make clean        remove all generated files
# ================================================================

# All 5 object files link into one .ko module
secure_driver-objs := core.o        \
                      fops.o        \
                      session.o     \
                      crypto.o      \
                      peripheral.o

obj-m := secure_driver.o

# Path to running kernel's build system
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# User-space compiler flags
CFLAGS := -Wall -Wextra -g -O0

.PHONY: all module user_app clean

all: module user_app
	@echo ""
	@echo "Build complete!"
	@echo "  Kernel module : secure_driver.ko (5 files linked)"
	@echo "  User binary   : user_app"
	@echo ""
	@echo "Next: sudo bash run.sh"

module:
	@echo "==> Compiling kernel module (5 source files)..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@echo "==> secure_driver.ko built"

user_app: user_app.c secure_driver.h
	@echo "==> Compiling user_app..."
	gcc $(CFLAGS) -o user_app user_app.c
	@echo "==> user_app built"

clean:
	@echo "==> Cleaning..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f user_app
	@echo "==> Clean complete"
