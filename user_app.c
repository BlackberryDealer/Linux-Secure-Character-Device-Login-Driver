/* ================================================================
 * user_app.c
 * User-Space Application for the Secure Character Device Driver
 *
 * CSC1107 Operating Systems — Project 12
 * Raspberry Pi 4 Model B · aarch64 · Raspberry Pi OS 64-bit
 *
 * ── What this program demonstrates ────────────────────────────
 *  • Opening /dev/secure_dev
 *  • Authenticating via ioctl(SECURE_IOCTL_LOGIN)
 *  • Sending  "Hello World from the user space"  via write()
 *  • Receiving "Hello World from the kernel space" via read()
 *  • Checking auth status via ioctl(SECURE_IOCTL_STATUS)
 *  • Advanced: requesting and verifying a session token
 *  • Demonstrating that read/write are blocked without login
 *  • Graceful logout via ioctl(SECURE_IOCTL_LOGOUT)
 *
 * ── Build ──────────────────────────────────────────────────────
 *  gcc -Wall -Wextra -o user_app user_app.c
 *
 * ── Run ────────────────────────────────────────────────────────
 *  ./user_app           — interactive menu
 *  ./user_app --demo    — automated full demonstration
 *
 * ── References ─────────────────────────────────────────────────
 *  [1] Linux man-pages: open(2), read(2), write(2), ioctl(2)
 *  [2] GenAI (ChatGPT) used for initial scaffolding; revised and
 *      extended by the student group for this project.
 * ================================================================ */

#include <stdio.h>       /* printf, fprintf, fgets, perror          */
#include <stdlib.h>      /* exit, EXIT_FAILURE                      */
#include <string.h>      /* strlen, strncpy, memset                 */
#include <fcntl.h>       /* open(), O_RDWR                          */
#include <unistd.h>      /* read(), write(), close()                */
#include <errno.h>       /* errno, EACCES, EFAULT                   */
#include <sys/ioctl.h>   /* ioctl()                                 */

/* Shared header: device name, ioctl commands, struct definitions  */
#include "secure_driver.h"

/* ================================================================
 * Terminal colour codes (makes output more readable)
 * ================================================================ */
#define CLR_RESET   "\033[0m"
#define CLR_RED     "\033[1;31m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_BOLD    "\033[1m"

/* ================================================================
 * Pretty-print helpers
 * ================================================================ */
#define DEVICE_PATH  "/dev/" DEVICE_NAME    /* "/dev/secure_dev"   */

static void print_banner(const char *title)
{
    printf("\n" CLR_BLUE
           "================================================================\n"
           "  %s\n"
           "================================================================\n"
           CLR_RESET, title);
}

static void print_ok(const char *msg)
{
    printf(CLR_GREEN "[  OK  ]" CLR_RESET "  %s\n", msg);
}

static void print_fail(const char *msg)
{
    printf(CLR_RED "[ FAIL ]" CLR_RESET "  %s\n", msg);
}

static void print_info(const char *msg)
{
    printf(CLR_CYAN "[ INFO ]" CLR_RESET "  %s\n", msg);
}

static void print_warn(const char *msg)
{
    printf(CLR_YELLOW "[ WARN ]" CLR_RESET "  %s\n", msg);
}

/* ================================================================
 * Global state: file descriptor + token storage
 * ================================================================ */
static int  g_fd          = -1;         /* open() handle for /dev/secure_dev   */
static char g_token[TOKEN_HEX_LEN];    /* Token received from kernel           */
static int  g_has_token   = 0;          /* Whether we hold a valid token        */

/* ================================================================
 * Core Operation Functions
 * Each returns 0 on success, -1 on failure.
 * ================================================================ */

/**
 * op_open_device() — Open /dev/secure_dev
 * Must be called before any other operation.
 */
static int op_open_device(void)
{
    if (g_fd >= 0) {
        print_warn("Device already open.");
        return 0;
    }

    g_fd = open(DEVICE_PATH, O_RDWR);
    if (g_fd < 0) {
        fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                "  open(%s) failed: %s\n"
                "         Is the kernel module loaded? (sudo insmod secure_driver.ko)\n",
                DEVICE_PATH, strerror(errno));
        return -1;
    }

    printf(CLR_GREEN "[  OK  ]" CLR_RESET
           "  Opened " CLR_BOLD "%s" CLR_RESET " (fd=%d)\n",
           DEVICE_PATH, g_fd);
    return 0;
}

/**
 * op_close_device() — Close the device file descriptor
 */
static void op_close_device(void)
{
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
        g_has_token = 0;
        memset(g_token, 0, sizeof(g_token));
        print_info("Device closed.");
    }
}

/**
 * op_login() — Authenticate via SECURE_IOCTL_LOGIN
 *
 * @username: null-terminated username string
 * @password: null-terminated password string (sent to kernel, hashed there)
 *
 * Returns 0 on success, -1 on failure.
 */
static int op_login(const char *username, const char *password)
{
    struct login_data creds;
    int ret;

    if (g_fd < 0) { print_fail("Device not open."); return -1; }

    memset(&creds, 0, sizeof(creds));
    strncpy(creds.username, username, MAX_USERNAME_LEN - 1);
    strncpy(creds.password, password, MAX_PASSWORD_LEN - 1);

    printf(CLR_CYAN "[ INFO ]" CLR_RESET
           "  Attempting login as '%s' ...\n", username);

    ret = ioctl(g_fd, SECURE_IOCTL_LOGIN, &creds);

    /* Wipe the plaintext password from user-space memory immediately */
    memset(creds.password, 0, sizeof(creds.password));

    if (ret == 0) {
        printf(CLR_GREEN "[  OK  ]" CLR_RESET
               "  Login successful! Welcome, " CLR_BOLD "%s" CLR_RESET "\n",
               username);
        return 0;
    } else {
        fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                "  Login DENIED (errno=%d: %s)\n"
                "         Check username/password and kernel dmesg logs.\n",
                errno, strerror(errno));
        return -1;
    }
}

/**
 * op_logout() — Invalidate session via SECURE_IOCTL_LOGOUT
 */
static int op_logout(void)
{
    int ret;
    if (g_fd < 0) { print_fail("Device not open."); return -1; }

    ret = ioctl(g_fd, SECURE_IOCTL_LOGOUT);
    if (ret == 0) {
        print_ok("Logged out successfully.");
        g_has_token = 0;
        memset(g_token, 0, sizeof(g_token));
        return 0;
    } else {
        fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                "  Logout failed: %s\n", strerror(errno));
        return -1;
    }
}

/**
 * op_check_status() — Query authentication status via SECURE_IOCTL_STATUS
 *
 * Returns 1 if authenticated, 0 if not, -1 on error.
 */
static int op_check_status(void)
{
    int status = 0, ret;
    if (g_fd < 0) { print_fail("Device not open."); return -1; }

    ret = ioctl(g_fd, SECURE_IOCTL_STATUS, &status);
    if (ret < 0) {
        fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                "  STATUS ioctl failed: %s\n", strerror(errno));
        return -1;
    }

    if (status == 1)
        print_ok("Authentication status: " CLR_GREEN "AUTHENTICATED" CLR_RESET);
    else
        print_warn("Authentication status: " CLR_YELLOW "NOT AUTHENTICATED" CLR_RESET);

    return status;
}

/**
 * op_write() — Send a message to the kernel via write()
 *
 * The kernel will store and log the message. Requires authentication.
 *
 * @message: Null-terminated string to send
 *
 * Returns number of bytes written on success, -1 on failure.
 */
static ssize_t op_write(const char *message)
{
    ssize_t ret;
    size_t  msg_len;

    if (g_fd < 0) { print_fail("Device not open."); return -1; }

    msg_len = strlen(message);

    printf(CLR_CYAN "[ INFO ]" CLR_RESET
           "  write() → kernel: \"%s\"\n", message);

    ret = write(g_fd, message, msg_len);

    if (ret < 0) {
        if (errno == EACCES)
            fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                    "  write() BLOCKED — not authenticated (EACCES)\n"
                    "         → Kernel logged this unauthorized attempt in dmesg\n");
        else
            fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                    "  write() failed: %s\n", strerror(errno));
        return -1;
    }

    printf(CLR_GREEN "[  OK  ]" CLR_RESET
           "  write() succeeded — %zd bytes sent to kernel\n", ret);
    return ret;
}

/**
 * op_read() — Retrieve the kernel's message via read()
 *
 * Returns the kernel response "Hello World from the kernel space".
 * Requires authentication.
 *
 * Returns number of bytes read on success, -1 on failure.
 */
static ssize_t op_read(void)
{
    char    buf[MAX_BUFFER_SIZE];
    ssize_t ret;

    if (g_fd < 0) { print_fail("Device not open."); return -1; }

    memset(buf, 0, sizeof(buf));

    printf(CLR_CYAN "[ INFO ]" CLR_RESET "  read() ← kernel ...\n");

    ret = read(g_fd, buf, sizeof(buf) - 1);

    if (ret < 0) {
        if (errno == EACCES)
            fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                    "  read() BLOCKED — not authenticated (EACCES)\n"
                    "         → Kernel logged this unauthorized attempt in dmesg\n");
        else
            fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                    "  read() failed: %s\n", strerror(errno));
        return -1;
    }

    if (ret == 0) {
        print_info("read() returned 0 bytes (EOF). "
                   "Close and reopen the device to reset position.");
        return 0;
    }

    buf[ret] = '\0';
    printf(CLR_GREEN "[  OK  ]" CLR_RESET
           "  read() received %zd bytes from kernel:\n"
           "         " CLR_BOLD "\"%s\"" CLR_RESET "\n", ret, buf);
    return ret;
}

/**
 * op_get_token() — Request a session token via SECURE_IOCTL_GET_TOKEN
 *
 * Stores the returned hex token in g_token for later verification.
 * Requires authentication.
 *
 * Returns 0 on success, -1 on failure.
 */
static int op_get_token(void)
{
    struct token_data tok;
    int ret;

    if (g_fd < 0) { print_fail("Device not open."); return -1; }

    memset(&tok, 0, sizeof(tok));

    print_info("Requesting session token from kernel ...");

    ret = ioctl(g_fd, SECURE_IOCTL_GET_TOKEN, &tok);
    if (ret < 0) {
        if (errno == EACCES)
            fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                    "  GET_TOKEN BLOCKED — not authenticated (EACCES)\n");
        else
            fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                    "  GET_TOKEN failed: %s\n", strerror(errno));
        return -1;
    }

    tok.token[TOKEN_HEX_LEN - 1] = '\0';   /* Defensive null-termination     */
    strncpy(g_token, tok.token, TOKEN_HEX_LEN - 1);
    g_has_token = 1;

    printf(CLR_GREEN "[  OK  ]" CLR_RESET
           "  Token received from kernel:\n"
           "         " CLR_BOLD "%s" CLR_RESET "\n"
           "         (This is hex(raw_token); kernel stores SHA-256(raw_token))\n",
           g_token);
    return 0;
}

/**
 * op_verify_token() — Verify the stored token via SECURE_IOCTL_VERIFY_TOKEN
 *
 * Sends g_token back to the kernel. The kernel re-hashes it and
 * compares with the stored SHA-256 hash to confirm authenticity.
 *
 * Returns 0 on success, -1 on failure.
 */
static int op_verify_token(void)
{
    struct token_data tok;
    int ret;

    if (g_fd < 0)  { print_fail("Device not open."); return -1; }
    if (!g_has_token) {
        print_warn("No token held. Call GET_TOKEN first.");
        return -1;
    }

    memset(&tok, 0, sizeof(tok));
    strncpy(tok.token, g_token, TOKEN_HEX_LEN - 1);

    printf(CLR_CYAN "[ INFO ]" CLR_RESET
           "  Sending token to kernel for verification:\n"
           "         %s\n", tok.token);

    ret = ioctl(g_fd, SECURE_IOCTL_VERIFY_TOKEN, &tok);
    if (ret == 0) {
        print_ok("Token VERIFIED by kernel — SHA-256 hash matched!");
        return 0;
    } else {
        if (errno == EACCES)
            fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                    "  Token REJECTED — hash mismatch (EACCES)\n"
                    "         → Kernel logged this in dmesg\n");
        else
            fprintf(stderr, CLR_RED "[ FAIL ]" CLR_RESET
                    "  VERIFY_TOKEN failed: %s\n", strerror(errno));
        return -1;
    }
}

/* ================================================================
 * Automated Demonstration Mode  (./user_app --demo)
 *
 * Runs a scripted sequence covering all driver features:
 *   1.  Open device
 *   2.  Show status: NOT authenticated
 *   3.  Try read without login    → BLOCKED (logged by kernel)
 *   4.  Try write without login   → BLOCKED (logged by kernel)
 *   5.  Login with correct creds  → SUCCESS
 *   6.  Show status: AUTHENTICATED
 *   7.  Write "Hello World from the user space"
 *   8.  Read  "Hello World from the kernel space"
 *   9.  Get session token
 *   10. Verify session token (SHA-256 hash validation)
 *   11. Logout
 *   12. Try write after logout    → BLOCKED again
 *   13. Close device
 * ================================================================ */
static void run_demo(void)
{
    print_banner("AUTOMATED DEMO — Secure Character Device Driver");
    printf("Credentials: username=" CLR_BOLD "admin" CLR_RESET
           "  password=" CLR_BOLD "SecurePass123" CLR_RESET "\n");

    /* ── 1. Open device ── */
    printf("\n" CLR_BOLD "── Step 1: Open device ──────────────────────────\n" CLR_RESET);
    if (op_open_device() < 0) {
        fprintf(stderr, "Cannot proceed without device. Exiting demo.\n");
        return;
    }

    /* ── 2. Status check (unauthenticated) ── */
    printf("\n" CLR_BOLD "── Step 2: Status check (expect: NOT authenticated) ─\n" CLR_RESET);
    op_check_status();

    /* ── 3. Unauthorized read ── */
    printf("\n" CLR_BOLD "── Step 3: read() WITHOUT login (expect: BLOCKED) ───\n" CLR_RESET);
    op_read();

    /* ── 4. Unauthorized write ── */
    printf("\n" CLR_BOLD "── Step 4: write() WITHOUT login (expect: BLOCKED) ──\n" CLR_RESET);
    op_write("This should be blocked");

    /* ── 5. Login ── */
    printf("\n" CLR_BOLD "── Step 5: Login with correct credentials ────────\n" CLR_RESET);
    if (op_login("admin", "SecurePass123") < 0) {
        print_fail("Login failed. Check module is loaded with default credentials.");
        op_close_device();
        return;
    }

    /* ── 6. Status check (authenticated) ── */
    printf("\n" CLR_BOLD "── Step 6: Status check (expect: AUTHENTICATED) ─────\n" CLR_RESET);
    op_check_status();

    /* ── 7. Write message ── */
    printf("\n" CLR_BOLD "── Step 7: write() — send message to kernel ─────\n" CLR_RESET);
    op_write("Hello World from the user space");

    /* ── 8. Read message ── */
    printf("\n" CLR_BOLD "── Step 8: read()  — receive message from kernel ─\n" CLR_RESET);
    /* Re-open to reset the file position so read() starts from byte 0 */
    op_close_device();
    op_open_device();
    op_login("admin", "SecurePass123");   /* Re-authenticate after reopen     */
    op_read();

    /* ── 9. Get token (advanced) ── */
    printf("\n" CLR_BOLD "── Step 9: GET_TOKEN — request session token ─────\n" CLR_RESET);
    op_get_token();

    /* ── 10. Verify token (advanced) ── */
    printf("\n" CLR_BOLD "── Step 10: VERIFY_TOKEN — hash validation ────────\n" CLR_RESET);
    op_verify_token();

    /* ── 11. Logout ── */
    printf("\n" CLR_BOLD "── Step 11: Logout ────────────────────────────────\n" CLR_RESET);
    op_logout();

    /* ── 12. Post-logout write attempt ── */
    printf("\n" CLR_BOLD "── Step 12: write() AFTER logout (expect: BLOCKED) ─\n" CLR_RESET);
    op_write("This should be blocked after logout");

    /* ── 13. Close device ── */
    printf("\n" CLR_BOLD "── Step 13: Close device ───────────────────────────\n" CLR_RESET);
    op_close_device();

    /* ── Summary ── */
    print_banner("DEMO COMPLETE");
    printf("Review kernel logs with:  " CLR_BOLD "dmesg | grep secure_dev\n" CLR_RESET);
    printf("You should see:\n");
    printf("  • Two [SECURITY ALERT] entries for unauthorized read/write (steps 3-4)\n");
    printf("  • [AUTH] LOGIN SUCCESS entry\n");
    printf("  • WROTE and READ log entries\n");
    printf("  • [TOKEN] token issue and verification entries\n");
    printf("  • [AUTH] LOGOUT and one more [SECURITY ALERT] (step 12)\n\n");
}

/* ================================================================
 * Interactive Menu Mode  (./user_app)
 * ================================================================ */

static void print_menu(void)
{
    printf("\n" CLR_BOLD CLR_BLUE
           "╔══════════════════════════════════════════════╗\n"
           "║    Secure Device Driver — Interactive Menu  ║\n"
           "╚══════════════════════════════════════════════╝\n"
           CLR_RESET);
    printf(CLR_BOLD " Device: %s   fd=%d   Token: %s\n" CLR_RESET,
           DEVICE_PATH,
           g_fd,
           g_has_token ? CLR_GREEN "HELD" CLR_RESET : CLR_YELLOW "none" CLR_RESET);
    printf("─────────────────────────────────────────────\n");
    printf("  1. Open device\n");
    printf("  2. Login\n");
    printf("  3. Write message to device\n");
    printf("  4. Read  message from device\n");
    printf("  5. Check authentication status\n");
    printf("  6. Get session token  (Advanced)\n");
    printf("  7. Verify session token (Advanced)\n");
    printf("  8. Logout\n");
    printf("  9. Close device\n");
    printf(" 10. Run bad-login test (wrong password)\n");
    printf("  0. Exit\n");
    printf("─────────────────────────────────────────────\n");
    printf("Choice: ");
    fflush(stdout);
}

/** Read a trimmed line from stdin into buf (max len-1 chars). */
static void read_input(const char *prompt, char *buf, size_t len)
{
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int)len, stdin)) {
        /* Strip trailing newline */
        size_t sl = strlen(buf);
        if (sl > 0 && buf[sl - 1] == '\n')
            buf[sl - 1] = '\0';
    } else {
        buf[0] = '\0';
    }
}

static void run_interactive(void)
{
    char choice_buf[8];
    int  choice;

    print_banner("CSC1107 Project 12 — Secure Character Device Driver");
    printf("Default credentials: " CLR_BOLD "admin / SecurePass123" CLR_RESET "\n");
    printf("Tip: run with " CLR_BOLD "--demo" CLR_RESET " for fully automated test.\n");

    while (1) {
        print_menu();
        read_input("", choice_buf, sizeof(choice_buf));
        choice = atoi(choice_buf);

        switch (choice) {

        case 1:   /* Open device */
            op_open_device();
            break;

        case 2: { /* Login */
            char uname[MAX_USERNAME_LEN];
            char passwd[MAX_PASSWORD_LEN];
            read_input("  Username: ", uname, sizeof(uname));
            read_input("  Password: ", passwd, sizeof(passwd));
            op_login(uname, passwd);
            memset(passwd, 0, sizeof(passwd));  /* Wipe from stack             */
            break;
        }

        case 3: { /* Write */
            char msg[MAX_BUFFER_SIZE];
            read_input("  Message to write: ", msg, sizeof(msg));
            op_write(msg);
            break;
        }

        case 4:   /* Read */
            /* Reset file position to 0 so we can read the message again without closing */
            if (g_fd >= 0) {
                lseek(g_fd, 0, SEEK_SET);
            }
            op_read();
            break;

        case 5:   /* Status */
            op_check_status();
            break;

        case 6:   /* Get token */
            op_get_token();
            break;

        case 7:   /* Verify token */
            op_verify_token();
            break;

        case 8:   /* Logout */
            op_logout();
            break;

        case 9:   /* Close device */
            op_close_device();
            break;

        case 10: { /* Bad login test */
            print_info("Testing login with WRONG password ...");
            op_login("admin", "WrongPassword!");
            print_info("Check dmesg for the [SECURITY ALERT] log entry.");
            break;
        }

        case 0:   /* Exit */
            print_info("Exiting. Closing device if open...");
            op_close_device();
            printf(CLR_GREEN "Goodbye!\n" CLR_RESET);
            return;

        default:
            print_warn("Unknown option. Enter 0-10.");
            break;
        }
    }
}

/* ================================================================
 * main() — Entry point
 * ================================================================ */
int main(int argc, char *argv[])
{
    /* Decide between demo and interactive mode */
    if (argc > 1 && strcmp(argv[1], "--demo") == 0) {
        run_demo();
    } else {
        run_interactive();
    }
    return 0;
}
