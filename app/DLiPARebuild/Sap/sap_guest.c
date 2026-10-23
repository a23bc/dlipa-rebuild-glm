/* SAP signer backed by the x86-64 CommerceKit guest.
 *
 * This is the probeapp chain (probeapp/x64probe.c) turned into a library: the
 * same loader, the same shim dispatch, the same Objective-C runtime, and the
 * same top-level driver loop that answers objc_msgSend. The diagnostic probes
 * from the probe app are deliberately absent - this file has one job.
 *
 * Layout of the container, little endian throughout:
 *
 *   0   "X64I"
 *   4   u32 version, must be 1
 *   8   u32 segment count
 *   12  u32 import count
 *   16  u32 rebase count
 *   20  u32 bind count
 *   24  u32 entry count
 *   28  segment table, 40 bytes per entry:
 *         char name[16], u64 vmaddr, u64 vmsize, u32 prot, u32 content_len
 *       followed by the segment contents, concatenated in order, then the
 *       import names (128 bytes each), the rebase list (8 each), the bind
 *       records (16 each) and the entry table (40 each).
 */

#include "sap_guest.h"
#include "sap_objc.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#define SAP_IMAGE_VERSION 1
#define SAP_MAX_SEGMENTS 16
#define SAP_MAX_IMPORTS 512
#define SAP_MAX_ENTRIES 16
#define SAP_MAX_ONCE 8

#define STUB_SLOT 16
#define DATA_SLOT 64

/* Guest address space. Fixed by the loader that produced the image: the rebase
 * and bind entries are absolute addresses in this same space. */
static const uint64_t k_base        = 0x100000000ULL;
static const uint64_t k_stub_base   = 0x700000000ULL;
static const uint64_t k_data_base   = 0x710000000ULL;
static const uint64_t k_stack_base  = 0x800000000ULL;
static const uint64_t k_heap_base   = 0x600000000ULL;
static const uint64_t k_heap_size   = 64ULL << 20;
static const uint64_t k_trampoline  = 0x500000000ULL;

struct sap_segment {
    char name[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint32_t prot;
    uint32_t content_len;
    const uint8_t *content;
};

struct sap_entry {
    char name[32];
    uint64_t addr;
};

struct sap_guest {
    uc_engine *uc;
    uint8_t *blob;
    size_t blob_len;

    struct sap_segment segs[SAP_MAX_SEGMENTS];
    uint32_t seg_count;
    uint32_t import_count;
    uint32_t rebase_count;
    uint32_t bind_count;
    uint32_t entry_count;

    char (*import_names)[128];
    struct sap_entry entries[SAP_MAX_ENTRIES];

    uint64_t heap_cursor;
    uint64_t stack_top;

    /* Shim state that has to survive between calls. */
    uint64_t once_inits[SAP_MAX_ONCE];
    int once_count;
    int io_iterator;
    uint32_t random_state;
    uint64_t errno_slot;
    uint64_t ticks;

    /* A pending objc_msgSend: the code hook records it and stops, the driver
     * performs the nested call at top level, then resumes after the call. */
    int msg_pending;
    uint64_t msg_receiver;
    uint64_t msg_selector;
    uint64_t msg_resume;

    /* Set when dispatch has no handler for an import: the run stops and the
     * name is the answer to "why". */
    int hit_slot;
    char stop_reason[256];

    sap_objc *objc;

    uint64_t context;
    uint8_t *certificate;
    size_t certificate_len;
    const uint8_t *hardware_id;
    size_t hardware_id_len;
    int ready;

    sap_post_fn post;
    void *userdata;

    sap_guest_stats stats;
    uc_hook hook_code;
    uc_hook hook_bad_read;
    uc_hook hook_bad_write;
    uc_hook hook_bad_fetch;
    uc_hook hook_syscall;
};

static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

static void set_error(char *error, size_t cap, const char *fmt, ...)
{
    if (error == NULL || cap == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(error, cap, fmt, ap);
    va_end(ap);
}

static int is_data_import(const char *name)
{
    if (strncmp(name, "_k", 2) == 0) {
        return 1;
    }
    return strcmp(name, "___stack_chk_guard") == 0;
}

typedef struct { uint64_t rdi, rsi, rdx, rcx, r8, r9; } sap_args;

static sap_args read_args(uc_engine *uc)
{
    sap_args a = {0, 0, 0, 0, 0, 0};
    uc_reg_read(uc, UC_X86_REG_RDI, &a.rdi);
    uc_reg_read(uc, UC_X86_REG_RSI, &a.rsi);
    uc_reg_read(uc, UC_X86_REG_RDX, &a.rdx);
    uc_reg_read(uc, UC_X86_REG_RCX, &a.rcx);
    uc_reg_read(uc, UC_X86_REG_R8, &a.r8);
    uc_reg_read(uc, UC_X86_REG_R9, &a.r9);
    return a;
}

static void set_rax(uc_engine *uc, uint64_t value)
{
    uc_reg_write(uc, UC_X86_REG_RAX, &value);
}

static int guest_copy(uc_engine *uc, uint64_t dst, uint64_t src, uint64_t n)
{
    uint8_t buf[4096];
    while (n > 0) {
        size_t chunk = n < sizeof(buf) ? (size_t)n : sizeof(buf);
        if (uc_mem_read(uc, src, buf, chunk) != UC_ERR_OK) return 0;
        if (uc_mem_write(uc, dst, buf, chunk) != UC_ERR_OK) return 0;
        src += chunk; dst += chunk; n -= chunk;
    }
    return 1;
}

static int guest_fill(uc_engine *uc, uint64_t dst, int byte, uint64_t n)
{
    uint8_t buf[4096];
    memset(buf, byte, sizeof(buf));
    while (n > 0) {
        size_t chunk = n < sizeof(buf) ? (size_t)n : sizeof(buf);
        if (uc_mem_write(uc, dst, buf, chunk) != UC_ERR_OK) return 0;
        dst += chunk; n -= chunk;
    }
    return 1;
}

static uint64_t guest_alloc(struct sap_guest *g, uint64_t size)
{
    uint64_t aligned = (size + 15) & ~15ULL;
    if (g->heap_cursor + aligned > k_heap_size) return 0;
    uint64_t at = k_heap_base + g->heap_cursor;
    g->heap_cursor += aligned;
    return at;
}
/* ---- import shims ------------------------------------------------------ */

/* Answered by category rather than by behaviour, the way probeapp does it.
 * An unhandled stub would return whatever rax happened to hold, and the guest
 * would believe it received a valid object and dereference it. */
static const char *const k_return_zero[] = {
    "_CFBundleGetMainBundle",
    "_CFDataGetBytePtr",
    "_CFDataGetLength",
    "_CFStringGetLength",
    "_CFStringGetMaximumSizeForEncoding",
    "_CFUUIDCreateString",
    "_CFStringCreateWithCStringNoCopy",
    "_CFRelease",
    "_IORegistryEntryFromPath",
    "_IORegistryEntrySearchCFProperty",
    "_IOServiceMatching",
    "_IOObjectRelease",
    "_getenv",
    "_pthread_self",
    "_close",
    "_close$UNIX2003",
    "_pthread_mutex_lock",
    "_pthread_mutex_unlock",
    "_pthread_rwlock_init",
    "_pthread_rwlock_init$UNIX2003",
};

static const char *const k_return_minus_one[] = {
    "_fcntl",
    "_fcntl$UNIX2003",
    "_lstat$INODE64",
    "_statfs",
    "_statfs$INODE64",
    "_statfs$UNIX2003",
    "_sysctl",
};

static const char *const k_return_uint32_max[] = {
    "_IOServiceGetMatchingService",
};

static const char *const k_return_fake_handle[] = {
    "_CFDictionaryGetValue",
    "_DADiskCopyDescription",
    "_DADiskCreateFromBSDName",
    "_DASessionCreate",
    "_IORegistryEntryCreateCFProperty",
};

static int name_in(const char *name, const char *const *table, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (strcmp(name, table[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Returns 1 when the import was served, 0 when nothing here knows it. */
static int dispatch(struct sap_guest *g, uint32_t slot)
{
    uc_engine *uc = g->uc;
    const char *name = g->import_names[slot];
    sap_args a = read_args(uc);

    /* CoreFoundation strings. Creation succeeds only for the three
     * machine-identity keys; a copy of the requested string would hand the
     * guest something it tries to parse as a serial number or a board id. */
    if (strcmp(name, "_CFStringCreateWithCString") == 0) {
        char text[256];
        memset(text, 0, sizeof(text));
        if (a.rsi != 0) {
            uc_mem_read(uc, a.rsi, text, sizeof(text) - 1);
        }
        int wanted = strcmp(text, "IOPlatformSerialNumber") == 0 ||
                     strcmp(text, "IOPlatformUUID") == 0 ||
                     strcmp(text, "board-id") == 0;
        set_rax(uc, wanted ? 0xffffffffffffffffULL : 0);
        return 1;
    }

    if (strcmp(name, "_CFStringGetCString") == 0) {
        if (a.rsi == 0 || a.rdx == 0) {
            set_rax(uc, 0);
            return 1;
        }
        char zero_byte = 0;
        uc_mem_write(uc, a.rsi, &zero_byte, 1);
        set_rax(uc, 1);
        return 1;
    }

    /* The IO registry walk. The guest asks for services matching "IOPlatform",
     * then walks the iterator looking for a serial number, a UUID and a board
     * id. A real machine answers with one entry; none makes the walk end, and
     * answering forever would hang it. */
    if (strcmp(name, "_IOServiceGetMatchingServices") == 0) {
        uint32_t fake = 0xffffffffu;
        if (a.rdx != 0) {
            uc_mem_write(uc, a.rdx, &fake, 4);
        }
        g->io_iterator = 0;
        set_rax(uc, 0);
        return 1;
    }

    if (strcmp(name, "_IOIteratorNext") == 0) {
        g->io_iterator++;
        set_rax(uc, (uint64_t)(g->io_iterator % 2));
        return 1;
    }

    if (strcmp(name, "_IORegistryEntryGetParentEntry") == 0) {
        uint32_t fake = 0xffffffffu;
        if (a.rdx != 0) {
            uc_mem_write(uc, a.rdx, &fake, 4);
        }
        set_rax(uc, 0);
        return 1;
    }

    if (strcmp(name, "_OSAtomicCompareAndSwap32Barrier") == 0) {
        uint32_t expected = (uint32_t)a.rdi;
        uint32_t replacement = (uint32_t)a.rsi;
        uint32_t current = 0;
        if (a.rdx == 0 || uc_mem_read(uc, a.rdx, &current, 4) != UC_ERR_OK ||
            current != expected) {
            set_rax(uc, 0);
            return 1;
        }
        uc_mem_write(uc, a.rdx, &replacement, 4);
        set_rax(uc, 1);
        return 1;
    }

    if (name_in(name, k_return_zero,
                sizeof(k_return_zero) / sizeof(k_return_zero[0]))) {
        set_rax(uc, 0);
        return 1;
    }
    if (name_in(name, k_return_minus_one,
                sizeof(k_return_minus_one) / sizeof(k_return_minus_one[0]))) {
        set_rax(uc, (uint64_t)-1);
        return 1;
    }
    if (name_in(name, k_return_uint32_max,
                sizeof(k_return_uint32_max) / sizeof(k_return_uint32_max[0]))) {
        set_rax(uc, 0xffffffffu);
        return 1;
    }
    if (name_in(name, k_return_fake_handle,
                sizeof(k_return_fake_handle) / sizeof(k_return_fake_handle[0]))) {
        /* The reference uses u64::MAX here, and the guest compares against it
         * directly in places, so the exact value matters. */
        set_rax(uc, 0xffffffffffffffffULL);
        return 1;
    }

    if (strcmp(name, "____chkstk_darwin") == 0 ||
        strcmp(name, "___chkstk_darwin") == 0) {
        /* Stack probe. The guest stack is fully mapped, so nothing to probe. */
        set_rax(uc, 0);
        return 1;
    }

    if (strcmp(name, "_memcpy") == 0 || strcmp(name, "___memcpy_chk") == 0 ||
        strcmp(name, "_memmove") == 0) {
        guest_copy(uc, a.rdi, a.rsi, a.rdx);
        set_rax(uc, a.rdi);
        return 1;
    }

    if (strcmp(name, "_memset") == 0 || strcmp(name, "___memset_chk") == 0 ||
        strcmp(name, "___bzero") == 0) {
        guest_fill(uc, a.rdi, (int)(a.rsi & 0xff), a.rdx);
        set_rax(uc, a.rdi);
        return 1;
    }

    if (strcmp(name, "_memcmp") == 0) {
        uint8_t x[256], y[256];
        uint64_t n = a.rdx, at = 0;
        int result = 0;
        while (at < n) {
            size_t chunk = (n - at) < sizeof(x) ? (size_t)(n - at) : sizeof(x);
            if (uc_mem_read(uc, a.rdi + at, x, chunk) != UC_ERR_OK) break;
            if (uc_mem_read(uc, a.rsi + at, y, chunk) != UC_ERR_OK) break;
            for (size_t i = 0; i < chunk; i++) {
                if (x[i] != y[i]) { result = (int)x[i] - (int)y[i]; break; }
            }
            if (result != 0) break;
            at += chunk;
        }
        set_rax(uc, (uint64_t)(int64_t)result);
        return 1;
    }

    if (strcmp(name, "_malloc") == 0 || strcmp(name, "_calloc") == 0) {
        uint64_t size = (strcmp(name, "_calloc") == 0) ? a.rdi * a.rsi : a.rdi;
        uint64_t at = guest_alloc(g, size);
        if (at != 0 && strcmp(name, "_calloc") == 0) {
            guest_fill(uc, at, 0, size);
        }
        set_rax(uc, at);
        return 1;
    }

    if (strcmp(name, "_free") == 0) {
        /* Bump allocator: freeing is a no-op, which is safe and leaks. */
        set_rax(uc, 0);
        return 1;
    }

    if (strcmp(name, "_realloc") == 0) {
        uint64_t at = guest_alloc(g, a.rsi);
        if (at != 0) {
            guest_copy(uc, at, a.rdi, a.rsi);
        }
        set_rax(uc, at);
        return 1;
    }

    if (strcmp(name, "_pthread_once") == 0) {
        /* Record and mark done, but do not call. Running the routine from
         * inside the hook is a re-entrant emulation and it breaks the caller.
         * The driver replays the recorded initialisers at top level. */
        if (a.rsi != 0 && g->once_count < SAP_MAX_ONCE) {
            g->once_inits[g->once_count++] = a.rsi;
        }
        /* pthread_once_t is 8 bytes on x86-64. Writing four left the upper
         * half alone, the sentinel never matched, and the guest asked for the
         * same initialiser on every round. */
        if (a.rdi != 0) {
            uint64_t done = ~0ULL;
            uc_mem_write(uc, a.rdi, &done, 8);
        }
        set_rax(uc, 0);
        return 1;
    }

    if (strncmp(name, "_pthread_mutex_", 15) == 0 ||
        strncmp(name, "_pthread_rwlock_", 16) == 0 ||
        strncmp(name, "_os_unfair_lock_", 16) == 0) {
        /* Single-threaded guest: locks are always uncontended. */
        set_rax(uc, 0);
        return 1;
    }

    if (strcmp(name, "_pthread_self") == 0) {
        set_rax(uc, 0x1000);
        return 1;
    }

    if (strcmp(name, "_gettimeofday") == 0) {
        if (a.rdi != 0) {
            uint32_t sec = 1700000000, usec = 0;
            uc_mem_write(uc, a.rdi, &sec, 4);
            uc_mem_write(uc, a.rdi + 4, &usec, 4);
        }
        set_rax(uc, 0);
        return 1;
    }

    if (strcmp(name, "_arc4random") == 0) {
        g->random_state = g->random_state * 1664525u + 1013904223u;
        set_rax(uc, g->random_state);
        return 1;
    }

    if (strcmp(name, "_arc4random_buf") == 0 || strcmp(name, "_getentropy") == 0) {
        guest_fill(uc, a.rdi, 0, a.rsi);
        set_rax(uc, 0);
        return 1;
    }

    if (strcmp(name, "_getuid") == 0) {
        set_rax(uc, 501);
        return 1;
    }

    if (strcmp(name, "___error") == 0) {
        if (g->errno_slot == 0) {
            g->errno_slot = guest_alloc(g, 8);
        }
        set_rax(uc, g->errno_slot);
        return 1;
    }

    if (strcmp(name, "_mach_absolute_time") == 0) {
        g->ticks += 1000;
        set_rax(uc, g->ticks);
        return 1;
    }

    /* objc_msgSend is not served from inside this hook: calling the resolved
     * method here would re-enter the engine. Record the request and stop; the
     * driver calls the method at top level and resumes at the return address
     * the call pushed. */
    if (strcmp(name, "_objc_msgSend") == 0 ||
        strcmp(name, "_objc_msgSend_fixup") == 0 ||
        strcmp(name, "_objc_retain") == 0 ||
        strcmp(name, "_objc_release") == 0 ||
        strcmp(name, "_objc_retainAutorelease") == 0 ||
        strcmp(name, "_objc_retainAutoreleasedReturnValue") == 0 ||
        strcmp(name, "_objc_autorelease") == 0 ||
        strcmp(name, "_objc_autoreleaseReturnValue") == 0) {
        g->msg_pending = 1;
        g->msg_receiver = a.rdi;
        g->msg_selector = a.rsi;
        uint64_t rsp = 0, ret = 0;
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
        uc_mem_read(uc, rsp, &ret, 8);
        g->msg_resume = ret;
        uc_emu_stop(uc);
        return 1;
    }

    if (strcmp(name, "_sysctlbyname") == 0) {
        char key[64];
        memset(key, 0, sizeof(key));
        if (a.rdi != 0) {
            uc_mem_read(uc, a.rdi, key, sizeof(key) - 1);
        }
        /* kern.osversion is the only key the exchange asks for. Answering -1
         * tells the caller the host has no version at all, which is not
         * something a real Mac would ever report, and the guest treats a
         * failed version query as a reason to abandon the exchange. */
        if (strcmp(key, "kern.osversion") == 0) {
            static const char version[] = "13A603";
            /* sysctlbyname(name, oldp, oldlenp, newp, newlen): the value
             * pointer is rsi and the length pointer is rdx. */
            uint64_t oldp = a.rsi;
            uint64_t oldlenp = a.rdx;
            uint64_t capacity = 0;
            if (oldlenp != 0) {
                uc_mem_read(uc, oldlenp, &capacity, 8);
            }
            uint64_t needed = sizeof(version);
            if (capacity >= needed && oldp != 0) {
                uc_mem_write(uc, oldp, version, needed);
                uc_mem_write(uc, oldlenp, &needed, 8);
                set_rax(uc, 0);
            } else if (oldp != 0 && capacity > 0) {
                /* A short buffer must still succeed: truncate into it. */
                uint64_t room = capacity < needed ? capacity : needed;
                uc_mem_write(uc, oldp, version, room);
                uc_mem_write(uc, oldlenp, &room, 8);
                set_rax(uc, 0);
            } else {
                uc_mem_write(uc, oldlenp, &needed, 8);
                set_rax(uc, (uint64_t)-1);
            }
            return 1;
        }
        set_rax(uc, (uint64_t)-1);
        return 1;
    }

    if (strcmp(name, "_confstr") == 0) {
        set_rax(uc, (uint64_t)-1);
        return 1;
    }

    return 0;
}
/* ---- hooks ------------------------------------------------------------- */

static void on_code(uc_engine *uc, uint64_t address, uint32_t size, void *user)
{
    (void)size;
    struct sap_guest *g = (struct sap_guest *)user;
    if (address < k_stub_base ||
        address >= k_stub_base + (uint64_t)g->import_count * STUB_SLOT) {
        return;
    }

    uint32_t slot = (uint32_t)((address - k_stub_base) / STUB_SLOT);
    if (slot >= g->import_count) return;

    if (dispatch(g, slot)) {
        return;
    }

    g->hit_slot = (int)slot;
    snprintf(g->stop_reason, sizeof(g->stop_reason),
             "no implementation for import %u (%s)", slot, g->import_names[slot]);
    uc_emu_stop(uc);
}

static void on_bad_read(uc_engine *uc, uc_mem_type type, uint64_t address,
                        int size, int64_t value, void *user)
{
    (void)uc; (void)type; (void)size; (void)value;
    struct sap_guest *g = (struct sap_guest *)user;
    if (g->stop_reason[0] == 0) {
        snprintf(g->stop_reason, sizeof(g->stop_reason),
                 "unmapped read at 0x%llx", (unsigned long long)address);
    }
}

static void on_bad_write(uc_engine *uc, uc_mem_type type, uint64_t address,
                         int size, int64_t value, void *user)
{
    (void)uc; (void)type; (void)size; (void)value;
    struct sap_guest *g = (struct sap_guest *)user;
    if (g->stop_reason[0] == 0) {
        snprintf(g->stop_reason, sizeof(g->stop_reason),
                 "unmapped write at 0x%llx", (unsigned long long)address);
    }
}

/* An unmapped fetch reports through the same six-argument shape as an
 * unmapped read, not the four-argument shape a code hook uses. Declaring it
 * the short way leaves user_data pointing at whatever was in the register that
 * the fourth argument travelled in, and the first store through it is a
 * SIGSEGV inside the hook. */
static void on_bad_fetch(uc_engine *uc, uc_mem_type type, uint64_t address,
                         int size, int64_t value, void *user)
{
    (void)uc; (void)type; (void)size; (void)value;
    struct sap_guest *g = (struct sap_guest *)user;
    if (g->stop_reason[0] == 0) {
        snprintf(g->stop_reason, sizeof(g->stop_reason),
                 "unmapped fetch at 0x%llx", (unsigned long long)address);
    }
}

static void on_syscall(uc_engine *uc, void *user)
{
    struct sap_guest *g = (struct sap_guest *)user;
    uint64_t number = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &number);
    if (g->stop_reason[0] == 0) {
        snprintf(g->stop_reason, sizeof(g->stop_reason),
                 "unhandled syscall %llu", (unsigned long long)number);
    }
    uc_emu_stop(uc);
}

/* ---- loader ------------------------------------------------------------ */

static int read_file(const char *path, uint8_t **out_blob, size_t *out_len,
                     char *error, size_t cap)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        set_error(error, cap, "cannot open image: %s", path);
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        set_error(error, cap, "cannot seek image");
        return -1;
    }
    long size = ftell(file);
    if (size <= 0) {
        fclose(file);
        set_error(error, cap, "image is empty");
        return -1;
    }
    rewind(file);

    uint8_t *blob = (uint8_t *)malloc((size_t)size);
    if (blob == NULL) {
        fclose(file);
        set_error(error, cap, "out of memory reading image");
        return -1;
    }
    size_t got = fread(blob, 1, (size_t)size, file);
    fclose(file);
    if (got != (size_t)size) {
        free(blob);
        set_error(error, cap, "short read on image");
        return -1;
    }
    *out_blob = blob;
    *out_len = (size_t)size;
    return 0;
}

static int prot_to_unicorn(uint32_t prot)
{
    int out = 0;
    if (prot & 1) out |= UC_PROT_READ;
    if (prot & 2) out |= UC_PROT_WRITE;
    if (prot & 4) out |= UC_PROT_EXEC;
    return out == 0 ? UC_PROT_ALL : out;
}

/* Parses the header, maps every segment, then walks the four tables that
 * follow the contents: import names, rebases, binds and entries. */
static int load_image(struct sap_guest *g, char *error, size_t cap)
{
    const uint8_t *blob = g->blob;
    if (g->blob_len < 28 || memcmp(blob, "X64I", 4) != 0) {
        set_error(error, cap, "not an X64I container");
        return -1;
    }
    if (rd32(blob + 4) != SAP_IMAGE_VERSION) {
        set_error(error, cap, "container version %u, expected %u",
                  rd32(blob + 4), SAP_IMAGE_VERSION);
        return -1;
    }

    g->seg_count = rd32(blob + 8);
    g->import_count = rd32(blob + 12);
    g->rebase_count = rd32(blob + 16);
    g->bind_count = rd32(blob + 20);
    g->entry_count = rd32(blob + 24);

    if (g->seg_count == 0 || g->seg_count > SAP_MAX_SEGMENTS ||
        g->import_count > SAP_MAX_IMPORTS ||
        g->entry_count > SAP_MAX_ENTRIES) {
        set_error(error, cap, "container counts out of range");
        return -1;
    }
    if (g->blob_len < 28 + (size_t)g->seg_count * 40) {
        set_error(error, cap, "segment table is truncated");
        return -1;
    }

    const uint8_t *cursor = blob + 28;
    for (uint32_t i = 0; i < g->seg_count; i++) {
        struct sap_segment *s = &g->segs[i];
        memcpy(s->name, cursor, 16);
        s->name[15] = 0;
        s->vmaddr = rd64(cursor + 16);
        s->vmsize = rd64(cursor + 24);
        s->prot = rd32(cursor + 32);
        s->content_len = rd32(cursor + 36);
        cursor += 40;
    }
    for (uint32_t i = 0; i < g->seg_count; i++) {
        struct sap_segment *s = &g->segs[i];
        if ((size_t)(cursor - blob) + s->content_len > g->blob_len) {
            set_error(error, cap, "segment %s content runs past the file", s->name);
            return -1;
        }
        s->content = cursor;
        cursor += s->content_len;
    }

    /* Import names, 128 bytes each. */
    size_t remaining = g->blob_len - (size_t)(cursor - blob);
    size_t import_bytes = (size_t)g->import_count * 128;
    size_t rebase_bytes = (size_t)g->rebase_count * 8;
    size_t bind_bytes = (size_t)g->bind_count * 16;
    size_t entry_bytes = (size_t)g->entry_count * 40;
    if (import_bytes + rebase_bytes + bind_bytes + entry_bytes > remaining) {
        set_error(error, cap, "tables run past the file");
        return -1;
    }

    for (uint32_t i = 0; i < g->import_count; i++) {
        memcpy(g->import_names[i], cursor, 128);
        g->import_names[i][127] = 0;
        cursor += 128;
    }
    const uint8_t *rebase = cursor;
    cursor += rebase_bytes;
    const uint8_t *bind = cursor;
    cursor += bind_bytes;

    /* Map the segments. */
    for (uint32_t i = 0; i < g->seg_count; i++) {
        struct sap_segment *s = &g->segs[i];
        uint64_t size = s->vmsize > s->content_len ? s->vmsize : s->content_len;
        if (size == 0) {
            continue;
        }
        uint64_t aligned = (size + 0xFFF) & ~0xFFFULL;
        uc_err err = uc_mem_map(g->uc, k_base + s->vmaddr, aligned,
                                prot_to_unicorn(s->prot));
        if (err != UC_ERR_OK) {
            set_error(error, cap, "cannot map segment %s at 0x%llx: %s",
                      s->name, (unsigned long long)s->vmaddr, uc_strerror(err));
            return -1;
        }
        if (s->content_len > 0) {
            err = uc_mem_write(g->uc, k_base + s->vmaddr, s->content,
                               s->content_len);
            if (err != UC_ERR_OK) {
                set_error(error, cap, "cannot write segment %s: %s",
                          s->name, uc_strerror(err));
                return -1;
            }
        }
    }

    /* One 16-byte stub slot per import, every slot a bare ret so an import
     * that is never bound returns to its caller instead of running into the
     * 0xCC padding. */
    uint64_t stub_size = ((uint64_t)g->import_count * STUB_SLOT + 0xFFF) & ~0xFFFULL;
    if (stub_size > 0) {
        uc_err err = uc_mem_map(g->uc, k_stub_base, stub_size, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            set_error(error, cap, "cannot map stubs: %s", uc_strerror(err));
            return -1;
        }
        uint8_t slot[STUB_SLOT];
        memset(slot, 0xCC, sizeof(slot));
        slot[0] = 0xC3;
        for (uint32_t i = 0; i < g->import_count; i++) {
            uc_mem_write(g->uc, k_stub_base + (uint64_t)i * STUB_SLOT,
                         slot, sizeof(slot));
        }
    }

    /* Data imports get their own 64-byte cell each. */
    uint32_t data_count = 0;
    for (uint32_t i = 0; i < g->import_count; i++) {
        if (is_data_import(g->import_names[i])) data_count++;
    }
    uint64_t data_size = ((uint64_t)data_count * DATA_SLOT + 0xFFF) & ~0xFFFULL;
    if (data_count > 0) {
        uc_err err = uc_mem_map(g->uc, k_data_base, data_size, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            set_error(error, cap, "cannot map data: %s", uc_strerror(err));
            return -1;
        }
    }

    uc_err err = uc_mem_map(g->uc, k_heap_base, k_heap_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        set_error(error, cap, "cannot map heap: %s", uc_strerror(err));
        return -1;
    }

    /* Rebase: every recorded address holds an interior pointer that has to
     * move by the image base. */
    for (uint32_t i = 0; i < g->rebase_count; i++) {
        uint64_t addr = rd64(rebase + (size_t)i * 8);
        uint64_t value = 0;
        if (uc_mem_read(g->uc, k_base + addr, &value, 8) != UC_ERR_OK) continue;
        value += k_base;
        uc_mem_write(g->uc, k_base + addr, &value, 8);
    }

    /* Bind: the target is a data cell or a stub slot, plus the addend. */
    uint32_t data_cursor = 0;
    for (uint32_t i = 0; i < g->bind_count; i++) {
        const uint8_t *rec = bind + (size_t)i * 16;
        uint64_t addr = rd64(rec);
        uint32_t slot = rd32(rec + 8);
        int32_t addend = (int32_t)rd32(rec + 12);
        uint64_t target = (slot < g->import_count && is_data_import(g->import_names[slot]))
                          ? k_data_base + (uint64_t)data_cursor++ * DATA_SLOT
                          : k_stub_base + (uint64_t)slot * STUB_SLOT;
        uint64_t value = target + (uint64_t)(int64_t)addend;
        uc_mem_write(g->uc, k_base + addr, &value, 8);
    }

    /* One page holding a bare ret: the place guest calls return to. */
    err = uc_mem_map(g->uc, k_trampoline, 0x1000, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        set_error(error, cap, "cannot map trampoline: %s", uc_strerror(err));
        return -1;
    }
    uint8_t ret_opcode = 0xC3;
    uc_mem_write(g->uc, k_trampoline, &ret_opcode, 1);

    const uint64_t stack_size = 0x100000;
    err = uc_mem_map(g->uc, k_stack_base, stack_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        set_error(error, cap, "cannot map stack: %s", uc_strerror(err));
        return -1;
    }
    g->stack_top = k_stack_base + stack_size;

    /* Entry table: 32-byte name, u64 address. The address is relative to the
     * image base like the segments. */
    for (uint32_t i = 0; i < g->entry_count; i++) {
        struct sap_entry *e = &g->entries[i];
        memcpy(e->name, cursor, 32);
        e->name[31] = 0;
        e->addr = k_base + rd64(cursor + 32);
        cursor += 40;
    }
    return 0;
}
/* ---- guest calls ------------------------------------------------------- */

/* Calls a guest function that takes no arguments. The return address is a
 * page containing a single ret, so the call comes back through the guest's own
 * stack discipline. Execution stops when the program counter reaches it. */
static uc_err call_guest(struct sap_guest *g, uint64_t fn, uint64_t *out_rax)
{
    uint64_t rsp = (g->stack_top - 0x800) & ~0xfULL;
    rsp -= 8;

    uint64_t return_address = k_trampoline;
    if (uc_mem_write(g->uc, rsp, &return_address, 8) != UC_ERR_OK) {
        return UC_ERR_WRITE_UNMAPPED;
    }
    uc_reg_write(g->uc, UC_X86_REG_RSP, &rsp);

    uc_err err = uc_emu_start(g->uc, fn, k_trampoline, 0, 0);
    if (err != UC_ERR_OK) {
        return err;
    }

    /* No instruction budget: a crypto routine's length depends on its input,
     * and stopping a call half way still reports success from uc_emu_start.
     * The real check is where it stopped. */
    uint64_t landed = 0;
    uc_reg_read(g->uc, UC_X86_REG_RIP, &landed);
    if (landed != k_trampoline) {
        return UC_ERR_EXCEPTION;
    }

    if (out_rax != NULL) {
        uc_reg_read(g->uc, UC_X86_REG_RAX, out_rax);
    }
    return err;
}

/* Calls a guest function with arguments. The frame is built as if a call had
 * already happened: [rsp] holds the return address, so rsp must be 8 mod 16 on
 * entry, and any arguments past the sixth live at [rsp+8], [rsp+16]. */
static uc_err call_guest_n(struct sap_guest *g, uint64_t fn, const uint64_t *args,
                           int nargs, uint64_t *out_rax)
{
    /* A nested call gets a frame below the one the outer call is using. The
     * outer frame lives just under stack_top, so this leaves 64 KB of clear
     * space between them: the two must not overlap, because the outer call is
     * suspended mid-function with its locals on the stack. */
    uint64_t rsp = (g->stack_top - 0x10000) & ~0xfULL;
    rsp -= 8;

    uint64_t return_address = k_trampoline;
    if (uc_mem_write(g->uc, rsp, &return_address, 8) != UC_ERR_OK) {
        return UC_ERR_WRITE_UNMAPPED;
    }

    for (int i = 6; i < nargs; i++) {
        uint64_t value = args[i];
        if (uc_mem_write(g->uc, rsp + 8 + (uint64_t)(i - 6) * 8, &value, 8) !=
            UC_ERR_OK) {
            return UC_ERR_WRITE_UNMAPPED;
        }
    }

    static const int regs[6] = {
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
        UC_X86_REG_RCX, UC_X86_REG_R8,  UC_X86_REG_R9,
    };
    for (int i = 0; i < nargs && i < 6; i++) {
        uint64_t value = args[i];
        uc_reg_write(g->uc, regs[i], &value);
    }

    uc_reg_write(g->uc, UC_X86_REG_RSP, &rsp);

    uc_err err = uc_emu_start(g->uc, fn, k_trampoline, 0, 0);
    if (err != UC_ERR_OK) {
        return err;
    }

    uint64_t landed = 0;
    uc_reg_read(g->uc, UC_X86_REG_RIP, &landed);
    if (landed != k_trampoline) {
        return UC_ERR_EXCEPTION;
    }

    if (out_rax != NULL) {
        uc_reg_read(g->uc, UC_X86_REG_RAX, out_rax);
    }
    return err;
}

/* Runs a guest function and services every objc_msgSend it makes.
 *
 * This is the probeapp driver loop. objc_msgSend cannot be answered inside the
 * code hook because calling the method there would re-enter the engine, so the
 * hook stops the run and records the request; here the method is called at top
 * level with the caller's own arguments, and the guest resumes at the return
 * address the call pushed with rax holding the result.
 *
 * Returns 0 when the call completed and the program counter came back. */
static int run_guest(struct sap_guest *g, uint64_t fn, const uint64_t *args,
                     int nargs, uint64_t *out_rax, char *error, size_t cap)
{
    g->msg_pending = 0;
    g->hit_slot = -1;
    g->stop_reason[0] = 0;

    uint64_t rsp = (g->stack_top - 0x800) & ~0xfULL;
    rsp -= 8;

    uint64_t return_address = k_trampoline;
    if (uc_mem_write(g->uc, rsp, &return_address, 8) != UC_ERR_OK) {
        set_error(error, cap, "cannot write the return address");
        return -1;
    }
    for (int i = 6; i < nargs; i++) {
        uint64_t value = args[i];
        if (uc_mem_write(g->uc, rsp + 8 + (uint64_t)(i - 6) * 8, &value, 8) !=
            UC_ERR_OK) {
            set_error(error, cap, "cannot write stack argument %d", i);
            return -1;
        }
    }

    static const int regs[6] = {
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
        UC_X86_REG_RCX, UC_X86_REG_R8,  UC_X86_REG_R9,
    };
    for (int i = 0; i < nargs && i < 6; i++) {
        uint64_t value = args[i];
        uc_reg_write(g->uc, regs[i], &value);
    }
    uc_reg_write(g->uc, UC_X86_REG_RSP, &rsp);

    uint64_t at = fn;
    for (;;) {
        g->msg_pending = 0;
        uc_err err = uc_emu_start(g->uc, at, k_trampoline, 0, 0);

        if (g->stop_reason[0] != 0) {
            set_error(error, cap, "%s", g->stop_reason);
            return -1;
        }

        if (g->msg_pending) {
            uint64_t isa = 0;
            const char *reason = NULL;
            uint64_t imp = 0;

            if (g->msg_receiver != 0 &&
                uc_mem_read(g->uc, g->msg_receiver, &isa, 8) == UC_ERR_OK) {
                imp = sap_objc_lookup(g->objc, isa, g->msg_selector, &reason);
            } else {
                reason = "receiver unreadable";
            }

            if (imp == 0) {
                g->stats.objc_misses++;
                snprintf(g->stats.objc_last_miss, sizeof(g->stats.objc_last_miss),
                         "%s", reason ? reason : "unknown");
                set_error(error, cap, "objc_msgSend unresolved: %s (receiver=0x%llx)",
                          g->stats.objc_last_miss,
                          (unsigned long long)g->msg_receiver);
                return -1;
            }

            /* Run the method with the caller's own arguments. Its return
             * address is already on the stack, so it returns straight to
             * msg_resume. */
            uint64_t method_args[6] = { 0, 0, 0, 0, 0, 0 };
            uc_reg_read(g->uc, UC_X86_REG_RDI, &method_args[0]);
            uc_reg_read(g->uc, UC_X86_REG_RSI, &method_args[1]);
            uc_reg_read(g->uc, UC_X86_REG_RDX, &method_args[2]);
            uc_reg_read(g->uc, UC_X86_REG_RCX, &method_args[3]);
            uc_reg_read(g->uc, UC_X86_REG_R8, &method_args[4]);
            uc_reg_read(g->uc, UC_X86_REG_R9, &method_args[5]);

            /* The nested call builds its frame at the top of the same guest
             * stack the outer call is using, which would overwrite the outer
             * frame and leave the resumed code walking over its own locals.
             * The stack pointer is saved here and restored after the method
             * returns, so the outer frame is untouched. */
            uint64_t outer_rsp = 0;
            uc_reg_read(g->uc, UC_X86_REG_RSP, &outer_rsp);

            uint64_t result = 0;
            uc_err merr = call_guest_n(g, k_base + imp, method_args, 6, &result);
            g->stats.objc_sends++;

            uc_reg_write(g->uc, UC_X86_REG_RSP, &outer_rsp);

            if (merr != UC_ERR_OK) {
                set_error(error, cap, "objc method 0x%llx faulted err=%u",
                          (unsigned long long)(k_base + imp), (unsigned)merr);
                return -1;
            }

            /* Put the result where the caller reads it and continue at the
             * instruction after the call. */
            set_rax(g->uc, result);
            at = g->msg_resume;
            continue;
        }

        if (err != UC_ERR_OK) {
            uint64_t stop = 0;
            uc_reg_read(g->uc, UC_X86_REG_RIP, &stop);
            set_error(error, cap, "guest stopped at 0x%llx (image+0x%llx): %s",
                      (unsigned long long)stop,
                      (unsigned long long)(stop >= k_base ? stop - k_base : 0),
                      uc_strerror(err));
            return -1;
        }
        break;
    }

    /* The only proof the guest returned is the program counter being back at
     * the trampoline. rax otherwise holds a leftover. */
    uint64_t landed = 0;
    uc_reg_read(g->uc, UC_X86_REG_RIP, &landed);
    if (landed != k_trampoline) {
        set_error(error, cap, "guest did not return from 0x%llx (stopped at 0x%llx)",
                  (unsigned long long)fn, (unsigned long long)landed);
        return -1;
    }

    if (out_rax != NULL) {
        uc_reg_read(g->uc, UC_X86_REG_RAX, out_rax);
    }
    return 0;
}

/* Replays the initialisers pthread_once asked for, at top level. Skipping them
 * leaves the globals they set at zero. */
static void run_once_inits(struct sap_guest *g)
{
    for (int k = 0; k < g->once_count; k++) {
        uint64_t once_rax = 0;
        call_guest(g, g->once_inits[k], &once_rax);
    }
}

/* ---- public API -------------------------------------------------------- */

sap_guest *sap_guest_new(const sap_guest_config *cfg, char *error, size_t cap)
{
    if (cfg == NULL || cfg->image_path == NULL) {
        set_error(error, cap, "no image path");
        return NULL;
    }
    if (cfg->hardware_id == NULL || cfg->hardware_id_len == 0 ||
        cfg->hardware_id_len > 20) {
        set_error(error, cap, "hardware id must be 1..20 bytes");
        return NULL;
    }

    struct sap_guest *g = (struct sap_guest *)calloc(1, sizeof(*g));
    if (g == NULL) {
        set_error(error, cap, "out of memory");
        return NULL;
    }
    g->post = cfg->post;
    g->userdata = cfg->userdata;
    g->hardware_id = cfg->hardware_id;
    g->hardware_id_len = cfg->hardware_id_len;
    g->random_state = 0x12345678u;
    g->ticks = 1000;
    g->hit_slot = -1;

    g->import_names = (char (*)[128])calloc(SAP_MAX_IMPORTS, 128);
    if (g->import_names == NULL) {
        set_error(error, cap, "out of memory for the import table");
        free(g);
        return NULL;
    }

    if (cfg->certificate != NULL && cfg->certificate_len > 0) {
        g->certificate = (uint8_t *)malloc(cfg->certificate_len);
        if (g->certificate == NULL) {
            set_error(error, cap, "out of memory copying the certificate");
            free(g->import_names);
            free(g);
            return NULL;
        }
        memcpy(g->certificate, cfg->certificate, cfg->certificate_len);
        g->certificate_len = cfg->certificate_len;
    }

    if (read_file(cfg->image_path, &g->blob, &g->blob_len, error, cap) != 0) {
        free(g->certificate);
        free(g->import_names);
        free(g);
        return NULL;
    }

    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &g->uc);
    if (err != UC_ERR_OK) {
        set_error(error, cap, "cannot open unicorn engine: %s", uc_strerror(err));
        free(g->blob);
        free(g->certificate);
        free(g->import_names);
        free(g);
        return NULL;
    }

    if (load_image(g, error, cap) != 0) {
        uc_close(g->uc);
        free(g->blob);
        free(g->certificate);
        free(g->import_names);
        free(g);
        return NULL;
    }

    /* The ObjC runtime needs no guest memory: it interns selector names and
     * assigns each class a guest address, all in host memory. */
    g->objc = sap_objc_shared();

    uint64_t stub_end = k_stub_base + (uint64_t)g->import_count * STUB_SLOT;
    if (uc_hook_add(g->uc, &g->hook_code, UC_HOOK_CODE, (void *)on_code, g,
                    k_stub_base, stub_end - 1) != UC_ERR_OK) {
        set_error(error, cap, "cannot install the stub hook");
        uc_close(g->uc);
        free(g->blob);
        free(g->certificate);
        free(g->import_names);
        free(g);
        return NULL;
    }

    uc_hook_add(g->uc, &g->hook_bad_read, UC_HOOK_MEM_READ_UNMAPPED,
                (void *)on_bad_read, g, 1, 0);
    uc_hook_add(g->uc, &g->hook_bad_write, UC_HOOK_MEM_WRITE_UNMAPPED,
                (void *)on_bad_write, g, 1, 0);
    uc_hook_add(g->uc, &g->hook_bad_fetch, UC_HOOK_MEM_FETCH_UNMAPPED,
                (void *)on_bad_fetch, g, 1, 0);
    uc_hook_add(g->uc, &g->hook_syscall, UC_HOOK_INSN, (void *)on_syscall, g,
                1, 0, UC_X86_INS_SYSCALL);

    return g;
}

void sap_guest_free(sap_guest *g)
{
    if (g == NULL) {
        return;
    }
    if (g->uc != NULL) {
        uc_close(g->uc);
    }
    free(g->certificate);
    free(g->import_names);
    free(g->blob);
    free(g);
}

void sap_guest_get_stats(const sap_guest *g, sap_guest_stats *out)
{
    if (g == NULL || out == NULL) {
        return;
    }
    *out = g->stats;
}
/* ---- handshake and sign ------------------------------------------------ */

/* The hardware block is a uint32 length followed by up to twenty ID bytes,
 * twenty-four bytes in total. The guest rejects anything outside 1..20. */
static uint64_t hardware_block(struct sap_guest *g)
{
    uint64_t at = guest_alloc(g, 24);
    if (at == 0) {
        return 0;
    }
    uint8_t block[24];
    memset(block, 0, sizeof(block));
    uint32_t n = (uint32_t)g->hardware_id_len;
    memcpy(block, &n, 4);
    memcpy(block + 4, g->hardware_id, g->hardware_id_len);
    uc_mem_write(g->uc, at, block, sizeof(block));
    return at;
}

/* Reads the pointer/length pair the guest leaves in the two output fields and
 * copies the bytes out. */
static int read_output(struct sap_guest *g, uint64_t pointer_field,
                       uint64_t length_field, uint8_t **out, size_t *out_len,
                       char *error, size_t cap)
{
    uint64_t pointer = 0, length = 0;
    uc_mem_read(g->uc, pointer_field, &pointer, 8);
    uc_mem_read(g->uc, length_field, &length, 8);

    if (length > (2ULL << 20)) {
        set_error(error, cap, "guest output is %llu bytes, maximum is 2 MB",
                  (unsigned long long)length);
        return -1;
    }
    if (length > 0 && pointer == 0) {
        set_error(error, cap, "guest returned a null output pointer");
        return -1;
    }
    if (length == 0) {
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    uint8_t *buffer = (uint8_t *)malloc((size_t)length);
    if (buffer == NULL) {
        set_error(error, cap, "out of memory copying guest output");
        return -1;
    }
    if (uc_mem_read(g->uc, pointer, buffer, (size_t)length) != UC_ERR_OK) {
        free(buffer);
        set_error(error, cap, "cannot read guest output at 0x%llx",
                  (unsigned long long)pointer);
        return -1;
    }
    *out = buffer;
    *out_len = (size_t)length;
    return 0;
}

/* One exchange leg. The same entry point serves both: the certificate leg
 * passes 200 and the reply leg 210, and the version decides which path the
 * guest takes. Eight arguments, so the last two travel on the stack. */
static int exchange(struct sap_guest *g, uint32_t version, const uint8_t *input,
                    size_t input_len, uint8_t **out, size_t *out_len,
                    int32_t *state, char *error, size_t cap)
{
    uint64_t exchange_addr = 0;
    for (uint32_t i = 0; i < g->entry_count; i++) {
        if (strcmp(g->entries[i].name, "_Mib5yocT") == 0) {
            exchange_addr = g->entries[i].addr;
            break;
        }
    }
    if (exchange_addr == 0) {
        set_error(error, cap, "image has no _Mib5yocT entry");
        return -1;
    }

    uint64_t hardware_addr = hardware_block(g);
    uint64_t input_addr = guest_alloc(g, input_len ? input_len : 1);
    uint64_t out_field = guest_alloc(g, 8);
    uint64_t len_field = guest_alloc(g, 8);
    uint64_t res_field = guest_alloc(g, 4);
    if (hardware_addr == 0 || input_addr == 0 || out_field == 0 ||
        len_field == 0 || res_field == 0) {
        set_error(error, cap, "guest heap exhausted");
        return -1;
    }

    uc_mem_write(g->uc, input_addr, input, input_len);
    uint64_t zero = 0;
    uint32_t zero32 = 0;
    uc_mem_write(g->uc, out_field, &zero, 8);
    uc_mem_write(g->uc, len_field, &zero, 8);
    uc_mem_write(g->uc, res_field, &zero32, 4);

    uint64_t args[8] = {
        (uint64_t)version, hardware_addr, g->context, input_addr,
        (uint64_t)input_len, out_field, len_field, res_field,
    };
    uint64_t status = 0;
    if (run_guest(g, exchange_addr, args, 8, &status, error, cap) != 0) {
        return -1;
    }

    g->stats.attempts++;
    int32_t code = (int32_t)status;
    if (code != 0) {
        set_error(error, cap, "SAP exchange returned %d", (int)code);
        return -1;
    }

    uint32_t result = 0;
    uc_mem_read(g->uc, res_field, &result, 4);
    if (state != NULL) {
        *state = (int32_t)result;
    }
    return read_output(g, out_field, len_field, out, out_len, error, cap);
}

int sap_guest_handshake(sap_guest *g, char *error, size_t cap)
{
    if (g == NULL) {
        return -1;
    }

    uint64_t initialize = 0;
    for (uint32_t i = 0; i < g->entry_count; i++) {
        if (strcmp(g->entries[i].name, "_cp2g1b9ro") == 0) {
            initialize = g->entries[i].addr;
            break;
        }
    }
    if (initialize == 0) {
        set_error(error, cap, "image has no _cp2g1b9ro entry");
        return -1;
    }

    /* An eight-byte slot the callee fills with a context handle, and the
     * hardware block. */
    uint64_t context_slot = guest_alloc(g, 8);
    uint64_t hardware_addr = hardware_block(g);
    if (context_slot == 0 || hardware_addr == 0) {
        set_error(error, cap, "guest heap exhausted");
        return -1;
    }
    uint64_t zero = 0;
    uc_mem_write(g->uc, context_slot, &zero, 8);

    /* The initialiser divides by a table size stored in __common, and indexes
     * a table through a pointer stored beside it. Both are zero on a cold
     * image, so the first call faults on the divide before it can create them.
     * The size and the pointer live at fixed image offsets, so an empty table
     * is placed there before the call. */
    {
        uint64_t table = guest_alloc(g, 64 * 4);
        if (table == 0) {
            set_error(error, cap, "guest heap exhausted");
            return -1;
        }
        uint8_t zeroes[64 * 4];
        memset(zeroes, 0, sizeof(zeroes));
        uc_mem_write(g->uc, table, zeroes, sizeof(zeroes));
        uint32_t table_size = 64;
        uc_mem_write(g->uc, k_base + 0x2bc874, &table_size, 4);
        uc_mem_write(g->uc, k_base + 0x2bbea0, &table, 8);
    }

    uint64_t args[2] = { context_slot, hardware_addr };
    uint64_t status = 0;

    /* The initialiser registers pthread_once initialisers it expects to have
     * run. probeapp replays them at top level and retries once; without that
     * the globals they set stay at zero and the first 32-bit divide in the
     * guest raises #DE. */
    int rc = run_guest(g, initialize, args, 2, &status, error, cap);
    if (rc != 0 || (int32_t)status != 0) {
        if (g->once_count > 0) {
            run_once_inits(g);
            uint64_t zero2 = 0;
            uc_mem_write(g->uc, context_slot, &zero2, 8);
            char retry_error[256];
            retry_error[0] = 0;
            rc = run_guest(g, initialize, args, 2, &status, retry_error,
                           sizeof(retry_error));
            if (rc != 0) {
                /* Report the retry's reason: the first attempt's is expected
                 * to be the cold-image fault. */
                set_error(error, cap, "%s", retry_error);
                return -1;
            }
        } else {
            if (rc != 0) {
                return -1;
            }
            set_error(error, cap, "SAP initialization returned %d", (int)status);
            return -1;
        }
    }
    g->stats.cert_status = (int32_t)status;
    if ((int32_t)status != 0) {
        set_error(error, cap, "SAP initialization returned %d", (int)status);
        return -1;
    }

    uint64_t context = 0;
    uc_mem_read(g->uc, context_slot, &context, 8);
    if (context == 0) {
        set_error(error, cap, "SAP initialization returned a null context");
        return -1;
    }
    g->context = context;

    if (g->certificate == NULL || g->certificate_len == 0) {
        set_error(error, cap, "no setup certificate");
        return -1;
    }

    /* The certificate is the input to the first leg: it is not a server
     * challenge, and an empty input can only ever produce an empty request. */
    uint8_t *request = NULL;
    size_t request_len = 0;
    int32_t state = 0;
    g->stats.cert_version = 200;
    if (exchange(g, 200, g->certificate, g->certificate_len,
                 &request, &request_len, &state, error, cap) != 0) {
        return -1;
    }
    g->stats.cert_state = state;
    if (state != 1) {
        free(request);
        set_error(error, cap, "SAP setup entered unexpected state %d", (int)state);
        return -1;
    }
    if (request_len == 0) {
        free(request);
        set_error(error, cap, "SAP setup message is empty");
        return -1;
    }

    /* The HTTP round trip belongs to the caller. */
    if (g->post == NULL) {
        free(request);
        set_error(error, cap, "no transport for the SAP setup message");
        return -1;
    }
    uint8_t *reply = (uint8_t *)malloc(64 * 1024);
    if (reply == NULL) {
        free(request);
        set_error(error, cap, "out of memory for the SAP reply");
        return -1;
    }
    size_t reply_len = 0;
    int post = g->post(request, request_len, reply, 64 * 1024, &reply_len,
                       g->userdata);
    free(request);
    if (post != 0 || reply_len == 0) {
        free(reply);
        set_error(error, cap, "SAP setup request failed (%d)", post);
        return -1;
    }

    /* The reply leg needs 210: the guest compares the version against 0xd2 and
     * leaves with -42091 when it is smaller. 200 is right for the certificate
     * leg only, and 211 and above fail too. */
    uint8_t *ignored = NULL;
    size_t ignored_len = 0;
    g->stats.reply_version = 210;
    int exchange_rc = exchange(g, 210, reply, reply_len, &ignored, &ignored_len,
                               &state, error, cap);
    free(reply);
    free(ignored);
    if (exchange_rc != 0) {
        return -1;
    }
    g->stats.reply_state = state;
    if (state != 0) {
        set_error(error, cap, "SAP setup completed in unexpected state %d",
                  (int)state);
        return -1;
    }
    g->stats.reply_status = 0;
    g->ready = 1;
    return 0;
}

int sap_guest_sign(sap_guest *g, const uint8_t *body, size_t body_len,
                   char **header, char *error, size_t cap)
{
    if (g == NULL || header == NULL) {
        return -1;
    }
    *header = NULL;
    if (!g->ready) {
        set_error(error, cap, "the SAP session is not handshaken");
        return -1;
    }

    uint64_t sign_addr = 0;
    for (uint32_t i = 0; i < g->entry_count; i++) {
        if (strcmp(g->entries[i].name, "_Fc3vhtJDvr") == 0) {
            sign_addr = g->entries[i].addr;
            break;
        }
    }
    if (sign_addr == 0) {
        set_error(error, cap, "image has no _Fc3vhtJDvr entry");
        return -1;
    }

    uint64_t input_addr = guest_alloc(g, body_len ? body_len : 1);
    uint64_t out_field = guest_alloc(g, 8);
    uint64_t len_field = guest_alloc(g, 8);
    if (input_addr == 0 || out_field == 0 || len_field == 0) {
        set_error(error, cap, "guest heap exhausted");
        return -1;
    }
    uc_mem_write(g->uc, input_addr, body, body_len);
    uint64_t zero = 0;
    uc_mem_write(g->uc, out_field, &zero, 8);
    uc_mem_write(g->uc, len_field, &zero, 8);

    /* The context, not its address: passing the slot instead made the
     * signature fail with the code the exchange had already put in a shared
     * field. */
    uint64_t args[5] = {
        g->context, input_addr, (uint64_t)body_len, out_field, len_field,
    };
    uint64_t status = 0;
    if (run_guest(g, sign_addr, args, 5, &status, error, cap) != 0) {
        return -1;
    }
    if ((int32_t)status != 0) {
        set_error(error, cap, "SAP signing returned %d", (int)status);
        return -1;
    }

    uint8_t *signature = NULL;
    size_t signature_len = 0;
    if (read_output(g, out_field, len_field, &signature, &signature_len,
                    error, cap) != 0) {
        return -1;
    }
    if (signature_len == 0) {
        free(signature);
        set_error(error, cap, "SAP signature is empty");
        return -1;
    }

    /* The header value is the signature in lowercase hex. */
    char *text = (char *)malloc(signature_len * 2 + 1);
    if (text == NULL) {
        free(signature);
        set_error(error, cap, "out of memory for the signature header");
        return -1;
    }
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < signature_len; i++) {
        text[i * 2] = digits[signature[i] >> 4];
        text[i * 2 + 1] = digits[signature[i] & 0xF];
    }
    text[signature_len * 2] = 0;
    free(signature);

    g->stats.signature_len = signature_len;
    *header = text;
    return 0;
}
