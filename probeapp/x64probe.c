/* Stage 2c: serve CoreFP's imports from the host.
 *
 * The loader places the image and points every bind at a 16-byte slot holding
 * a bare ret. A code hook scoped to that slot region fires before the ret
 * executes, dispatches on the import's name, sets the return value, and then
 * lets the ret run normally. That way a call returns to its caller through the
 * ordinary stack mechanism instead of the host having to fake a return
 * address.
 *
 * An import with no handler still stops the run and is named in the report.
 * That keeps each device round-trip productive: whatever is printed is the
 * next thing to implement. */

#include "x64probe.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include "objcruntime.h"
#include "sapcert.h"

/* CommerceKit carries 392 imports, so the old ceiling of 320 rejected it
 * outright with "counts out of range". */
#define MAX_IMPORTS 512
#define MAX_SEGMENTS 16
#define MAX_ENTRIES 16
#define STUB_SLOT 16
#define DATA_SLOT 64

static void append(char *out, size_t cap, size_t *used, const char *fmt, ...)
{
	if (*used + 1 >= cap) {
		return;
	}
	va_list args;
	va_start(args, fmt);
	int written = vsnprintf(out + *used, cap - *used, fmt, args);
	va_end(args);
	if (written < 0) {
		return;
	}
	*used += (size_t)written;
	if (*used >= cap) {
		*used = cap - 1;
	}
}

static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

static uint64_t g_base           = 0x100000000ULL;
static uint64_t g_stub_base      = 0x700000000ULL;
static uint64_t g_data_base      = 0x710000000ULL;
static uint64_t g_stack_base     = 0x800000000ULL;
static uint64_t g_heap_base      = 0x600000000ULL;
static uint64_t g_heap_size      = 64ULL << 20;
static uint64_t g_heap_cursor    = 0;

static int is_data_import(const char *name)
{
	if (strncmp(name, "_k", 2) == 0) {
		return 1;
	}
	return strcmp(name, "___stack_chk_guard") == 0;
}

typedef struct {
	char name[16];
	uint64_t vmaddr;
	uint64_t vmsize;
	uint32_t prot;
	uint32_t content_len;
	const uint8_t *content;
} seg_t;

typedef struct {
	char name[32];
	uint64_t addr;
} entry_t;

typedef struct {
	uc_engine *uc;
	uint64_t stub_base;
	uint32_t stub_count;
	char (*names)[128];
	uint32_t *served;
	uint32_t served_total;
	int hit_slot;
	uint64_t fault_addr;
	int fault_kind;
	uint64_t once_inits[8];
	int once_count;
	uint64_t syscall_nr;
	int syscall_seen;
	char sysctl_names[6][64];
	int sysctl_count;
	uint64_t load_base;
	int objc_sends;
	int objc_misses;
	char objc_last_miss[128];
	/* A pending objc_msgSend: the hook records it and stops, the driver loop
	 * performs the nested call at top level, then resumes after the call. */
	int msg_pending;
	uint64_t msg_receiver;
	uint64_t msg_selector;
	uint64_t msg_resume;
	/* Every distinct stub slot that was entered, in order, so a missing call can
	 * be distinguished from a call that was served silently. */
	uint16_t visited[32];
	int visited_count;
	/* Coverage of the guest's own code: one bit per 4 KB page of the loaded
	 * image. Sampling the program counter only shows where it is between
	 * slices; this records every page it ever executed, which is what tells
	 * the analysed path apart from the one actually taken. */
	uint8_t *code_pages;
	uint64_t code_base;
	uint64_t code_pages_count;
	/* Exact entry hits. A page being covered only says the region ran; it does
	 * not say the function's first instruction did, and a 40 KB span can hold
	 * dozens of functions. These are recorded per address. */
	uint64_t entry_addrs[8];
	uint32_t entry_hits[8];
	int entry_count;
	/* The guest walks the IO registry looking for machine identity. The walk
	 * must terminate, so the iterator yields one entry and then zero. */
	int io_iterator;
	/* The exchange's error path runs through a flattened state machine: a jump
	 * table indexed by a state number, with the error constant selected when
	 * that number takes a particular value. Recording every state the machine
	 * visits turns "it returned -42023" into "it went through these states and
	 * diverged here". */
	uint32_t vm_states[256];
	int vm_state_count;
	uint64_t vm_site;
	/* The order imports are called in separates "a shim returned the wrong
	 * value" from "the guest took a different path". The two are impossible to
	 * tell apart from a status code alone. */
	char call_trace[1536];
	size_t call_trace_len;
	/* Every shim call with its arguments and result, encoded so that two
	 * machines with different address spaces can be compared: zero, all-ones
	 * and pointers become z, u and p, and only genuinely small integers keep
	 * their value. Addresses differ between runs; what a shim was asked and
	 * what it answered does not. */
	char shim_trace[6144];
	size_t shim_trace_len;
	/* Program counters inside the exchange, as image offsets. A call that
	 * returns a fixed error without calling a single import cannot be told
	 * apart from a correct call by its result; the first few hundred addresses
	 * it executes can be compared against a run that is known to work. */
	uint32_t pc_trace[256];
	int pc_count;
	/* The first addresses match on both runs, so the difference is later.
	 * A ring of the most recent addresses shows where each run stopped, which
	 * is the same information read from the other end. */
	uint32_t pc_last[256];
	uint64_t pc_total;
	/* Both runs start and finish the same way, so the difference is in the
	 * middle. A checksum per 65536 instructions lines the two runs up without
	 * shipping three million addresses: the first block that differs is the
	 * region to look at, and it is small enough to disassemble. */
	uint32_t pc_block[64];
	/* The whitening loop at 8a7c0 is fixed-length, so its instruction count
	 * cannot differ between two runs that reach it. Recording its arguments
	 * and how many times it is entered separates "a different buffer" from
	 * "a different number of passes". */
	uint64_t loop_rcx, loop_rsi, loop_hits;
} hook_ctx_t;

typedef struct {
	uint64_t rdi, rsi, rdx, rcx, r8, r9;
} args_t;

static args_t read_args(uc_engine *uc)
{
	args_t a = {0};
	uc_reg_read(uc, UC_X86_REG_RDI, &a.rdi);
	uc_reg_read(uc, UC_X86_REG_RSI, &a.rsi);
	uc_reg_read(uc, UC_X86_REG_RDX, &a.rdx);
	uc_reg_read(uc, UC_X86_REG_RCX, &a.rcx);
	uc_reg_read(uc, UC_X86_REG_R8,  &a.r8);
	uc_reg_read(uc, UC_X86_REG_R9,  &a.r9);
	return a;
}

static void set_rax(uc_engine *uc, uint64_t value)
{
	uc_reg_write(uc, UC_X86_REG_RAX, &value);
}

/* Copies guest-to-guest in host-sized chunks; returns 0 if any page is
 * unmapped, so a bad pointer surfaces as a failed memcpy rather than a fault. */
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

static uint64_t guest_alloc(uint64_t size)
{
	uint64_t aligned = (size + 15) & ~15ULL;
	if (g_heap_cursor + aligned > g_heap_size) return 0;
	uint64_t at = g_heap_base + g_heap_cursor;
	g_heap_cursor += aligned;
	return at;
}

/* objc_msgSend is not served from inside the dispatch hook.
 *
 * The hook runs while uc_emu_start is executing; calling the resolved method
 * from there would mean re-entering the engine. Instead the hook stops the run
 * and records the request, and the driver loop below performs the nested call
 * at top level. The guest is then resumed at the instruction after the send,
 * with rax holding the method's result. */

/* Returns 1 when the import was served, 0 when it has no handler. */
/* Imports answered by category rather than by behaviour.
 *
 * The reference implementation groups these the same way: a long list of
 * CoreFoundation and IOKit calls whose results the guest never inspects, a
 * few that must fail, and a few that must return a handle-shaped non-zero
 * value. Answering them individually would be forty near-identical branches,
 * and leaving them unanswered is worse than it sounds: an unhandled stub
 * returns whatever rax happened to hold, so the guest believes it received a
 * valid object and dereferences it.
 *
 * _IORegistryEntryFromPath matters most here. The reference makes it fail
 * deliberately, which is how the guest falls back to the hardware ID passed
 * in by the caller. Returning a non-zero leftover instead sends it down a
 * path that reads properties off a handle that never existed. */
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

/* pthread_once has to run its routine before it returns. A caller that reads
 * the global the routine was supposed to set otherwise sees zero, and deferring
 * it was the largest remaining difference between this build and a local run of
 * the same image - the local one runs it and reaches state 1.
 *
 * The routine is guest code, so calling it from inside the stub hook means a
 * re-entrant emulation. Every general register is saved and restored, and the
 * call gets a stack area of its own, so the interrupted context resumes exactly
 * where it was. */
#define ONCE_TRAMPOLINE 0x500000000ULL
static uc_err call_guest(uc_engine *uc, uint64_t fn, uint64_t stack_top,
                         uint64_t trampoline, uint64_t *out_rax);

/* The HTTP round trip between the two exchange calls belongs to the app: the
 * guest is synchronous and has no network stack, and the fallback in the
 * library code is written for a host process.
 *
 * The driver calls back out at the one point where it holds the request the
 * library just produced, then feeds whatever comes back into the second
 * exchange. Returning 0 means the reply is valid. */
static sap_post_fn g_sap_post;

/* One line of context from the app about what the round trip actually did:
 * status code, body length, first bytes. Without it a failed callback is just
 * a number, and the difference between "wrong endpoint", "error page" and
 * "binary plist we could not read" is several rounds of guessing. */
static char g_sap_note[256];

void x64probe_set_post(sap_post_fn fn)
{
	g_sap_post = fn;
}

void x64probe_set_post_note(const char *text)
{
	if (text == 0) {
		g_sap_note[0] = 0;
		return;
	}
	snprintf(g_sap_note, sizeof(g_sap_note), "%s", text);
}

static void tok(char *dst, size_t cap, uint64_t v)
{
	if (v == 0) {
		snprintf(dst, cap, "z");
	} else if (v == ~0ULL) {
		snprintf(dst, cap, "u");
	} else if (v == 0xffffffffULL) {
		snprintf(dst, cap, "w");
	} else if (v >= 0x100000000ULL) {
		snprintf(dst, cap, "p");
	} else {
		snprintf(dst, cap, "%llx", (unsigned long long)v);
	}
}

static void trace_shim(hook_ctx_t *ctx, const char *name,
                       const uint64_t *args, uint64_t ret)
{
	char a0[24], a1[24], a2[24], r[24];
	tok(a0, sizeof(a0), args[0]);
	tok(a1, sizeof(a1), args[1]);
	tok(a2, sizeof(a2), args[2]);
	tok(r, sizeof(r), ret);
	int n = snprintf(ctx->shim_trace + ctx->shim_trace_len,
	                 sizeof(ctx->shim_trace) - ctx->shim_trace_len,
	                 "%s(%s,%s,%s)=%s ", name + 1, a0, a1, a2, r);
	if (n > 0 && ctx->shim_trace_len + (size_t)n < sizeof(ctx->shim_trace)) {
		ctx->shim_trace_len += (size_t)n;
	}
}

static void trace_call(hook_ctx_t *ctx, const char *name)
{
	size_t n = strlen(name);
	if (ctx->call_trace_len + n + 2 >= sizeof(ctx->call_trace)) {
		return;
	}
	memcpy(ctx->call_trace + ctx->call_trace_len, name, n);
	ctx->call_trace_len += n;
	ctx->call_trace[ctx->call_trace_len++] = ' ';
	ctx->call_trace[ctx->call_trace_len] = 0;
}

static int dispatch(hook_ctx_t *ctx, uint32_t slot)
{
	uc_engine *uc = ctx->uc;
	const char *name = ctx->names[slot];
	args_t a = read_args(uc);
	trace_call(ctx, name);

	/* CoreFoundation strings. The reference implements these for real rather
	 * than stubbing them, which suggests the guest compares or copies the
	 * values. Because creation and lookup are both answered here, the handle
	 * can simply be the address of a copy of the C string: nothing else ever
	 * inspects it. */
	/* CoreFoundation strings, answered the way the reference answers them.
	 *
	 * Creation succeeds only for the three machine-identity keys; everything
	 * else gets a null string. Lookup always yields the empty string, which is
	 * enough because the caller checks for success, not for content.
	 *
	 * Returning a copy of the requested string - as an earlier version of this
	 * probe did - is worse than returning empty: it hands back a value the guest
	 * will try to parse as a serial number or a board id. */
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
		ctx->io_iterator = 0;
		set_rax(uc, 0);
		return 1;
	}

	if (strcmp(name, "_IOIteratorNext") == 0) {
		ctx->io_iterator++;
		set_rax(uc, (uint64_t)(ctx->io_iterator % 2));
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

	if (name_in(name, k_return_zero, sizeof(k_return_zero) / sizeof(k_return_zero[0]))) {
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

	if (strcmp(name, "_memcpy") == 0 ||
	    strcmp(name, "___memcpy_chk") == 0 ||
	    strcmp(name, "_memmove") == 0) {
		guest_copy(uc, a.rdi, a.rsi, a.rdx);
		set_rax(uc, a.rdi);
		return 1;
	}

	if (strcmp(name, "_memset") == 0 ||
	    strcmp(name, "___memset_chk") == 0 ||
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
		uint64_t at = guest_alloc(size);
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
		uint64_t at = guest_alloc(a.rsi);
		if (at != 0) {
			guest_copy(uc, at, a.rdi, a.rsi);
		}
		set_rax(uc, at);
		return 1;
	}

	/* The lengths are the prefix lengths without the terminating NUL:
	 * "_pthread_mutex_" is 15, the other two are 16. Counting the NUL makes
	 * the comparison fail against every real symbol. */
	if (strcmp(name, "_pthread_once") == 0) {
		/* Run the initialiser now, once, if the once word says it has not run
		 * yet. Deferring it left the globals it sets at zero, which is what
		 * the exchange's early exit was reacting to. */
		/* Record and mark done, but do not call. Running the routine from
		 * inside the hook is a re-entrant emulation and it breaks the caller:
		 * the same change made a locally working build fail, so the deferred
		 * form is the one that matches. */
		if (a.rsi != 0 && ctx->once_count < 8) {
			ctx->once_inits[ctx->once_count++] = a.rsi;
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
		static uint32_t state = 0x12345678;
		state = state * 1664525u + 1013904223u;
		set_rax(uc, state);
		return 1;
	}

	if (strcmp(name, "_arc4random_buf") == 0 || strcmp(name, "_getentropy") == 0) {
		uint64_t n = (strcmp(name, "_getentropy") == 0) ? a.rsi : a.rsi;
		guest_fill(uc, a.rdi, 0, n);
		set_rax(uc, 0);
		return 1;
	}

	if (strcmp(name, "_getuid") == 0) {
		set_rax(uc, 501);
		return 1;
	}

	if (strcmp(name, "___error") == 0) {
		/* Guest errno slot, allocated once. */
		static uint64_t slot_addr = 0;
		if (slot_addr == 0) slot_addr = guest_alloc(8);
		set_rax(uc, slot_addr);
		return 1;
	}

	if (strcmp(name, "_mach_absolute_time") == 0) {
		static uint64_t ticks = 1000;
		ticks += 1000;
		set_rax(uc, ticks);
		return 1;
	}

	/* objc_msgSend cannot be answered here: calling the resolved method would
	 * re-enter uc_emu_start while it is running. Record the send and stop; the
	 * driver loop calls the method at top level and resumes at the return
	 * address the call pushed. */
	if (strcmp(name, "_objc_msgSend") == 0 ||
	    strcmp(name, "_objc_msgSend_fixup") == 0 ||
	    strcmp(name, "_objc_retain") == 0 ||
	    strcmp(name, "_objc_release") == 0 ||
	    strcmp(name, "_objc_retainAutorelease") == 0 ||
	    strcmp(name, "_objc_retainAutoreleasedReturnValue") == 0 ||
	    strcmp(name, "_objc_autorelease") == 0 ||
	    strcmp(name, "_objc_autoreleaseReturnValue") == 0) {
		ctx->msg_pending = 1;
		ctx->msg_receiver = a.rdi;
		ctx->msg_selector = a.rsi;
		/* The call pushed a return address; the driver resumes there. */
		uint64_t rsp = 0, ret = 0;
		uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
		uc_mem_read(uc, rsp, &ret, 8);
		ctx->msg_resume = ret;
		uc_emu_stop(uc);
		return 1;
	}

	if (strcmp(name, "_sysctlbyname") == 0) {
		char key[64];
		memset(key, 0, sizeof(key));
		uc_mem_read(uc, a.rdi, key, sizeof(key) - 1);

		if (ctx->sysctl_count < 6) {
			snprintf(ctx->sysctl_names[ctx->sysctl_count],
			         sizeof(ctx->sysctl_names[0]), "%s", key);
			ctx->sysctl_count++;
		}

		/* kern.osversion is the only key the exchange asks for, and it is a
		 * plain string query: oldval, oldlenp. Answering -1 tells the caller
		 * the host has no version at all, which is not something a real Mac
		 * would ever report. A 10.9-era string is the consistent answer. */
		if (strcmp(key, "kern.osversion") == 0) {
			static const char version[] = "13A603";
			/* sysctlbyname(name, oldp, oldlenp, newp, newlen): the value
			 * pointer is rsi and the length pointer is rdx. Reading them from
			 * rdi and rsi - one register late - wrote the version string over
			 * the caller's length and answered -1. The guest treats a failed
			 * version query as a reason to abandon the exchange. */
			uint64_t oldp = a.rsi;
			uint64_t oldlenp = a.rdx;

			uint64_t capacity = 0;
			if (oldlenp != 0) {
				uc_mem_read(uc, oldlenp, &capacity, 8);
			}
			uint64_t needed = sizeof(version);

			if (capacity >= needed && oldp != 0) {
				uc_mem_write(uc, oldp, version, needed);
				uint64_t written = needed;
				uc_mem_write(uc, oldlenp, &written, 8);
				set_rax(uc, 0);
			} else {
				/* A short buffer must still succeed. The guest asks for the OS
				 * version as part of building the machine's identity, and a
				 * failure here is not a detail it shrugs off - it abandons the
				 * exchange. Truncating into whatever room it offered keeps the
				 * call successful, which is what a real host would do when the
				 * value fits in the caller's buffer. */
				if (oldp != 0 && capacity > 0) {
					uint64_t room = capacity < needed ? capacity : needed;
					uc_mem_write(uc, oldp, version, room);
					uint64_t written = room;
					uc_mem_write(uc, oldlenp, &written, 8);
					set_rax(uc, 0);
				} else {
					uc_mem_write(uc, oldlenp, &needed, 8);
					set_rax(uc, (uint64_t)-1);
				}
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

/* An unhandled syscall surfaces as UC_ERR_EXCEPTION, which says nothing about
 * what was called. Capturing the number in rax turns a dead end into a fact.
 *
 * The handler stops the run rather than pretending to implement the syscall:
 * guessing wrong here would move the failure somewhere less obvious. */
static void on_syscall(uc_engine *uc, void *user)
{
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	uint64_t number = 0;
	uc_reg_read(uc, UC_X86_REG_RAX, &number);
	ctx->syscall_nr = number;
	ctx->syscall_seen = 1;
	uc_emu_stop(uc);
}

/* Calls a guest function that takes no arguments.
 *
 * The return address is a page containing a single ret, so the call comes back
 * through the guest's own stack discipline. Execution stops when the program
 * counter reaches that page. This is what makes it possible to run the
 * pthread_once initialisers that the shim records: skipping them left a global
 * at zero, and the first 32-bit divide in CommerceKit then raised #DE. */
static uc_err call_guest_n(uc_engine *uc, uint64_t fn, uint64_t stack_top,
                           uint64_t trampoline, const uint64_t *args,
                           int nargs, uint64_t *out_rax)
{
	/* The frame is built as if a call had already happened: [rsp] holds the
	 * return address, so rsp must be 8 mod 16 on entry, and any arguments past
	 * the sixth live at [rsp+8], [rsp+16]. */
	uint64_t rsp = (stack_top - 0x800) & ~0xfULL;
	rsp -= 8;

	uint64_t return_address = trampoline;
	if (uc_mem_write(uc, rsp, &return_address, 8) != UC_ERR_OK) {
		return UC_ERR_WRITE_UNMAPPED;
	}

	for (int i = 6; i < nargs; i++) {
		uint64_t value = args[i];
		if (uc_mem_write(uc, rsp + 8 + (uint64_t)(i - 6) * 8, &value, 8) != UC_ERR_OK) {
			return UC_ERR_WRITE_UNMAPPED;
		}
	}

	static const int regs[6] = {
		UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
		UC_X86_REG_RCX, UC_X86_REG_R8,  UC_X86_REG_R9,
	};
	for (int i = 0; i < nargs && i < 6; i++) {
		uint64_t value = args[i];
		uc_reg_write(uc, regs[i], &value);
	}

	uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

	/* No instruction budget: a crypto routine's length depends on its input,
	 * and stopping a call half way still reports success from uc_emu_start.
	 * The real check is where it stopped.
	 *
	 * If the program counter is not back at the trampoline, the guest did not
	 * return - it ran out of budget or wandered off - and whatever is in rax is
	 * a leftover, not a result. Treating that as a return value is how a
	 * mid-function code address came to be reported as a status code. */
	uc_err err = uc_emu_start(uc, fn, trampoline, 0, 0);
	if (err != UC_ERR_OK) {
		return err;
	}

	uint64_t landed = 0;
	uc_reg_read(uc, UC_X86_REG_RIP, &landed);
	if (landed != trampoline) {
		return UC_ERR_EXCEPTION;
	}

	if (out_rax != NULL) {
		uc_reg_read(uc, UC_X86_REG_RAX, out_rax);
	}
	return err;
}

static uc_err call_guest(uc_engine *uc, uint64_t fn, uint64_t stack_top,
                         uint64_t trampoline, uint64_t *out_rax)
{
	return call_guest_n(uc, fn, stack_top, trampoline, NULL, 0, out_rax);
}

/* Records the page a guest instruction came from. One bit per 4 KB, so the
 * whole image costs a few kilobytes of host memory. */
/* Records the state number the dispatcher is about to test. EAX holds it at
 * the comparison, before the jump table uses it. */
static void on_vm_state(uc_engine *uc, uint64_t address, uint32_t size, void *user)
{
	(void)address; (void)size;
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	uint64_t rax = 0;
	if (uc_reg_read(uc, UC_X86_REG_RAX, &rax) != UC_ERR_OK) {
		return;
	}
	if (ctx->vm_state_count < 256) {
		ctx->vm_states[ctx->vm_state_count++] = (uint32_t)rax;
	}
}

/* Records the first addresses executed inside the exchange. */
static void on_exchange_pc(uc_engine *uc, uint64_t address, uint32_t size, void *user)
{
	(void)uc; (void)size;
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	if (ctx->pc_count < 256) {
		ctx->pc_trace[ctx->pc_count++] = (uint32_t)(address - g_base);
	}
	ctx->pc_last[ctx->pc_total % 256] = (uint32_t)(address - g_base);
	{
		uint32_t block = (uint32_t)(ctx->pc_total >> 12);
		if (block < 64) {
			ctx->pc_block[block] = ctx->pc_block[block] * 16777619u
			                     + (uint32_t)(address - g_base) + 1u;
		}
	}
	ctx->pc_total++;
}

static void on_whiten(uc_engine *uc, uint64_t address, uint32_t size, void *user)
{
	(void)address; (void)size;
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	if (ctx->loop_hits == 0) {
		uc_reg_read(uc, UC_X86_REG_RCX, &ctx->loop_rcx);
		uc_reg_read(uc, UC_X86_REG_RSI, &ctx->loop_rsi);
	}
	ctx->loop_hits++;
}

static void on_guest_code(uc_engine *uc, uint64_t address, uint32_t size, void *user)
{
	(void)uc; (void)size;
	hook_ctx_t *ctx = (hook_ctx_t *)user;

	for (int i = 0; i < ctx->entry_count; i++) {
		if (ctx->entry_addrs[i] == address) {
			ctx->entry_hits[i]++;
			break;
		}
	}

	if (address < ctx->code_base) {
		return;
	}
	uint64_t index = (address - ctx->code_base) >> 12;
	if (index < ctx->code_pages_count) {
		ctx->code_pages[index >> 3] |= (uint8_t)(1u << (index & 7));
	}
}

static void on_code(uc_engine *uc, uint64_t address, uint32_t size, void *user)
{
	(void)size;
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	if (address < ctx->stub_base ||
	    address >= ctx->stub_base + (uint64_t)ctx->stub_count * STUB_SLOT) {
		return;
	}

	uint32_t slot = (uint32_t)((address - ctx->stub_base) / STUB_SLOT);
	if (slot >= ctx->stub_count) return;

	if (ctx->visited_count < 32) {
		int seen = 0;
		for (int i = 0; i < ctx->visited_count; i++) {
			if (ctx->visited[i] == (uint16_t)slot) { seen = 1; break; }
		}
		if (!seen) {
			ctx->visited[ctx->visited_count++] = (uint16_t)slot;
		}
	}

	uint64_t shim_args[3] = { 0, 0, 0 };
	uc_reg_read(uc, UC_X86_REG_RDI, &shim_args[0]);
	uc_reg_read(uc, UC_X86_REG_RSI, &shim_args[1]);
	uc_reg_read(uc, UC_X86_REG_RDX, &shim_args[2]);

	if (dispatch(ctx, slot)) {
		uint64_t ret = 0;
		uc_reg_read(uc, UC_X86_REG_RAX, &ret);
		trace_shim(ctx, ctx->names[slot], shim_args, ret);
		ctx->served[slot]++;
		ctx->served_total++;
		return;
	}

	ctx->hit_slot = (int)slot;
	uc_emu_stop(uc);
}

static void on_bad_read(uc_engine *uc, uc_mem_type type, uint64_t address,
                        int size, int64_t value, void *user)
{
	(void)uc; (void)type; (void)size; (void)value;
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	ctx->fault_addr = address; ctx->fault_kind = 1;
}

static void on_bad_write(uc_engine *uc, uc_mem_type type, uint64_t address,
                         int size, int64_t value, void *user)
{
	(void)uc; (void)type; (void)size; (void)value;
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	ctx->fault_addr = address; ctx->fault_kind = 2;
}

/* An unmapped fetch reports through the same six-argument shape as an
 * unmapped read, not the four-argument shape a code hook uses. Declaring it
 * the short way leaves user_data pointing at whatever was in the register
 * that the fourth argument travelled in, and the first store through it is a
 * SIGSEGV inside the hook - which is exactly what the crash log showed. */
static void on_bad_fetch(uc_engine *uc, uc_mem_type type, uint64_t address,
                         int size, int64_t value, void *user)
{
	(void)uc; (void)type; (void)size; (void)value;
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	ctx->fault_addr = address; ctx->fault_kind = 3;
}

void x64probe_report(const char *path, int mode, char *out, size_t cap)
{
	if (cap == 0) return;
	out[0] = 0;
	size_t used = 0;

	FILE *file = fopen(path, "rb");
	if (file == NULL) { append(out, cap, &used, "[X64] cannot open image: %s\n", path); return; }
	fseek(file, 0, SEEK_END); long size = ftell(file); fseek(file, 0, SEEK_SET);
	uint8_t *blob = (uint8_t *)malloc((size_t)size);
	if (blob == NULL || fread(blob, 1, (size_t)size, file) != (size_t)size) {
		append(out, cap, &used, "[X64] short read\n"); fclose(file); free(blob); return;
	}
	fclose(file);

	if (memcmp(blob, "X64I", 4) != 0 || rd32(blob + 4) != 1) {
		append(out, cap, &used, "[X64] bad magic or version\n"); free(blob); return;
	}

	uint32_t seg_count = rd32(blob + 8), import_count = rd32(blob + 12);
	uint32_t rebase_count = rd32(blob + 16), bind_count = rd32(blob + 20);
	uint32_t entry_count = rd32(blob + 24);

	if (seg_count > MAX_SEGMENTS || import_count > MAX_IMPORTS || entry_count > MAX_ENTRIES) {
		append(out, cap, &used, "[X64] counts out of range\n"); free(blob); return;
	}
	append(out, cap, &used, "[X64] image: %u segments, %u imports, %u rebases, %u binds, %u entries\n",
	       seg_count, import_count, rebase_count, bind_count, entry_count);

	seg_t segs[MAX_SEGMENTS];
	const uint8_t *cursor = blob + 28;
	for (uint32_t i = 0; i < seg_count; i++) {
		memcpy(segs[i].name, cursor, 16);
		segs[i].vmaddr = rd64(cursor + 16);
		segs[i].vmsize = rd64(cursor + 24);
		segs[i].prot = rd32(cursor + 32);
		segs[i].content_len = rd32(cursor + 36);
		cursor += 40;
	}
	for (uint32_t i = 0; i < seg_count; i++) { segs[i].content = cursor; cursor += segs[i].content_len; }

	static char import_names[MAX_IMPORTS][128];
	for (uint32_t i = 0; i < import_count; i++) { memcpy(import_names[i], cursor, 128); cursor += 128; }

	const uint8_t *rebase_data = cursor; cursor += (size_t)rebase_count * 8;
	const uint8_t *bind_data = cursor; cursor += (size_t)bind_count * 16;

	entry_t entries[MAX_ENTRIES];
	for (uint32_t i = 0; i < entry_count; i++) {
		memcpy(entries[i].name, cursor, 32);
		entries[i].addr = rd64(cursor + 32);
		cursor += 40;
	}

	uc_engine *uc = NULL;
	uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err != UC_ERR_OK) { append(out, cap, &used, "[X64] uc_open failed: %u\n", err); free(blob); return; }

	for (uint32_t i = 0; i < seg_count; i++) {
		uint64_t map_size = (segs[i].vmsize + 0xfff) & ~0xfffULL;
		if (uc_mem_map(uc, g_base + segs[i].vmaddr, (size_t)map_size, UC_PROT_ALL) != UC_ERR_OK) {
			append(out, cap, &used, "[X64] map %s failed\n", segs[i].name);
			uc_close(uc); free(blob); return;
		}
		if (segs[i].content_len > 0 &&
		    uc_mem_write(uc, g_base + segs[i].vmaddr, segs[i].content, segs[i].content_len) != UC_ERR_OK) {
			append(out, cap, &used, "[X64] write %s failed\n", segs[i].name);
			uc_close(uc); free(blob); return;
		}
	}
	append(out, cap, &used, "[X64] segments mapped at %#llx\n", (unsigned long long)g_base);

	/* The ObjC runtime needs no guest memory: it interns selector names and
	 * assigns each class a guest address, all in host memory. */
	objc_runtime_init();
	append(out, cap, &used, "[X64] objc runtime: %d classes, %d selectors\n",
	       objc_class_count(), objc_selector_count());

	uint32_t stub_count = import_count;
	uint64_t stub_size = ((uint64_t)stub_count * STUB_SLOT + 0xfff) & ~0xfffULL;
	if (uc_mem_map(uc, g_stub_base, (size_t)stub_size, UC_PROT_ALL) != UC_ERR_OK) {
		append(out, cap, &used, "[X64] stub map failed (%llu bytes)\n", (unsigned long long)stub_size);
		uc_close(uc); free(blob); return;
	}
	uint8_t stub_code[STUB_SLOT];
	memset(stub_code, 0xcc, sizeof(stub_code));
	stub_code[0] = 0xc3;
	for (uint32_t i = 0; i < stub_count; i++) {
		uc_mem_write(uc, g_stub_base + (uint64_t)i * STUB_SLOT, stub_code, STUB_SLOT);
	}

	uint32_t data_count = 0;
	for (uint32_t i = 0; i < import_count; i++) { if (is_data_import(import_names[i])) data_count++; }
	uint64_t data_size = ((uint64_t)data_count * DATA_SLOT + 0xfff) & ~0xfffULL;
	if (data_count > 0 && uc_mem_map(uc, g_data_base, (size_t)data_size, UC_PROT_ALL) != UC_ERR_OK) {
		append(out, cap, &used, "[X64] data map failed\n"); uc_close(uc); free(blob); return;
	}

	if (uc_mem_map(uc, g_heap_base, (size_t)g_heap_size, UC_PROT_ALL) != UC_ERR_OK) {
		append(out, cap, &used, "[X64] heap map failed\n"); uc_close(uc); free(blob); return;
	}

	for (uint32_t i = 0; i < rebase_count; i++) {
		uint64_t addr = rd64(rebase_data + (size_t)i * 8);
		uint64_t value = 0;
		if (uc_mem_read(uc, g_base + addr, &value, 8) != UC_ERR_OK) continue;
		value += g_base;
		uc_mem_write(uc, g_base + addr, &value, 8);
	}
	append(out, cap, &used, "[X64] applied %u rebases\n", rebase_count);

	uint32_t data_cursor = 0;
	for (uint32_t i = 0; i < bind_count; i++) {
		const uint8_t *rec = bind_data + (size_t)i * 16;
		uint64_t addr = rd64(rec);
		uint32_t slot = rd32(rec + 8);
		int32_t addend = (int32_t)rd32(rec + 12);
		uint64_t target = (slot < import_count && is_data_import(import_names[slot]))
		                 ? g_data_base + (uint64_t)data_cursor++ * DATA_SLOT
		                 : g_stub_base + (uint64_t)slot * STUB_SLOT;
		uint64_t value = target + (uint64_t)(int64_t)addend;
		uc_mem_write(uc, g_base + addr, &value, 8);
	}
	append(out, cap, &used, "[X64] applied %u binds\n", bind_count);

	/* One page holding a bare ret: the place guest calls return to. */
	uint64_t trampoline = 0x500000000ULL;
	if (uc_mem_map(uc, trampoline, 0x1000, UC_PROT_ALL) != UC_ERR_OK) {
		append(out, cap, &used, "[X64] trampoline map failed\n");
		uc_close(uc); free(blob); return;
	}
	uint8_t ret_opcode = 0xc3;
	uc_mem_write(uc, trampoline, &ret_opcode, 1);

	if (uc_mem_map(uc, g_stack_base, 0x100000, UC_PROT_ALL) != UC_ERR_OK) {
		append(out, cap, &used, "[X64] stack map failed\n"); uc_close(uc); free(blob); return;
	}
	uint64_t rsp = g_stack_base + 0x100000 - 0x100;
	uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

	if (entry_count == 0) { append(out, cap, &used, "[X64] no entries\n"); uc_close(uc); free(blob); return; }

	static uint32_t served[MAX_IMPORTS];
	memset(served, 0, sizeof(served));

	hook_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.uc = uc;
	ctx.stub_base = g_stub_base;
	ctx.stub_count = stub_count;
	ctx.names = import_names;
	ctx.served = served;
	ctx.hit_slot = -1;

	/* Coverage of the guest image's own code, one bit per 4 KB page. The
	 * image is under 3 MB, so this is under a kilobyte of bitmap. */
	uint64_t code_span = 0;
	for (uint32_t i = 0; i < seg_count; i++) {
		uint64_t end = segs[i].vmaddr + segs[i].vmsize;
		if (end > code_span) {
			code_span = end;
		}
	}
	ctx.code_base = g_base;
	ctx.code_pages_count = (code_span >> 12) + 1;

	/* Watch the first instruction of every export. Page coverage cannot tell
	 * "this function ran" from "something in its page ran". */
	ctx.entry_count = 0;
	for (uint32_t i = 0; i < entry_count && ctx.entry_count < 8; i++) {
		ctx.entry_addrs[ctx.entry_count] = g_base + entries[i].addr;
		ctx.entry_hits[ctx.entry_count] = 0;
		ctx.entry_count++;
	}
	ctx.code_pages = (uint8_t *)calloc((size_t)((ctx.code_pages_count + 7) / 8) + 1, 1);

	uc_hook hook, h1, h2, h3, h4, h5, h6, h7, h8;
	uc_hook_add(uc, &hook, UC_HOOK_CODE, on_code, &ctx,
	            g_stub_base, g_stub_base + (uint64_t)stub_count * STUB_SLOT - 1);
	if (ctx.code_pages != NULL) {
		uc_hook_add(uc, &h5, UC_HOOK_CODE, on_guest_code, &ctx,
		            g_base, g_base + code_span);
	}

	/* One instruction window: the state-number comparison that precedes the
	 * jump table. Watching it costs nothing when the machine is not running. */
	ctx.vm_site = g_base + 0x1b889d;
	uc_hook_add(uc, &h6, UC_HOOK_CODE, on_vm_state, &ctx,
	            ctx.vm_site, ctx.vm_site + 8);

	/* Addresses executed inside the exchange, which starts at image 0x88cd0. */
	uc_hook_add(uc, &h7, UC_HOOK_CODE, on_exchange_pc, &ctx,
	            g_base + 0x88cd0, g_base + 0x92000);
	uc_hook_add(uc, &h8, UC_HOOK_CODE, on_whiten, &ctx,
	            g_base + 0x8a7c0, g_base + 0x8a7c5);
	uc_hook_add(uc, &h1, UC_HOOK_MEM_READ_UNMAPPED, on_bad_read, &ctx, 1, 0);
	uc_hook_add(uc, &h2, UC_HOOK_MEM_WRITE_UNMAPPED, on_bad_write, &ctx, 1, 0);
	uc_hook_add(uc, &h3, UC_HOOK_MEM_FETCH_UNMAPPED, on_bad_fetch, &ctx, 1, 0);
	uc_hook_add(uc, &h4, UC_HOOK_INSN, on_syscall, &ctx, 1, 0, UC_X86_INS_SYSCALL);

	/* Every candidate entry gets its own run.
	 *
	 * The first export returned after a single stack probe, which is not what
	 * an entry point looks like, and guessing which of the six is the real one
	 * costs a rebuild per wrong guess. Running all of them - module
	 * initialisers first - makes one install answer the whole question: which
	 * entry does the most work, and what does each of them reach for.
	 *
	 * Registers are reset between runs and the stack pointer returned to the
	 * top. Memory side effects from an earlier entry are not undone, so this is
	 * a survey rather than six clean experiments; the ordering below puts the
	 * initialisers first for that reason. */
	for (uint32_t e = 0; e < entry_count; e++) {
		/* mode 1 is the real thing: only _cp2g1b9ro, with the arguments the
		 * SAP driver passes. Everything else stays a zero-argument survey. */
		if (mode >= 1 && strcmp(entries[e].name, "_cp2g1b9ro") != 0) {
			continue;
		}

		uint64_t zero = 0;
		uc_reg_write(uc, UC_X86_REG_RAX, &zero);
		uc_reg_write(uc, UC_X86_REG_RBX, &zero);
		uc_reg_write(uc, UC_X86_REG_RCX, &zero);
		uc_reg_write(uc, UC_X86_REG_RDX, &zero);
		uc_reg_write(uc, UC_X86_REG_RSI, &zero);
		uc_reg_write(uc, UC_X86_REG_RDI, &zero);
		uc_reg_write(uc, UC_X86_REG_R8, &zero);
		uc_reg_write(uc, UC_X86_REG_R9, &zero);
		uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

		ctx.hit_slot = -1;
		ctx.fault_addr = 0;
		ctx.fault_kind = 0;
		uint32_t before = ctx.served_total;

		uint64_t where = g_base + entries[e].addr;

		uint64_t context_slot = 0;
		uint64_t hardware_addr = 0;
		if (mode >= 1) {
			/* Layout copied from the working arm64 driver: an eight-byte slot
			 * the callee fills with a context handle, and a 24-byte hardware
			 * block holding a uint32 length followed by up to twenty ID bytes. */
			context_slot = guest_alloc(8);
			hardware_addr = guest_alloc(24);
			/* The hardware ID is a MAC address, not an arbitrary blob: the
			 * reference implementation derives it from the interface's
			 * hardware address and rejects anything outside 1..20 bytes. Six
			 * bytes of a locally administered address is what a real client
			 * sends. */
			uint32_t length = 6;
			/* A globally unique address with Apple's own OUI. The previous
			 * value started with 0x02, which is the locally administered bit -
			 * legal on the wire, but not something a real NIC reports, and the
			 * guest may well reject it when it builds its machine identity. */
			uint8_t id[6] = { 0x3c, 0x22, 0xfb, 0x12, 0x34, 0x56 };
			uc_mem_write(uc, hardware_addr, &length, 4);
			uc_mem_write(uc, hardware_addr + 4, id, sizeof(id));
			/* The initialiser divides by a table size stored in __common, and
			 * indexes a table through a pointer stored beside it. Both are zero
			 * on a cold image, so the first call faults on the divide before it
			 * can create them.
			 *
			 * Running the once-initialisers and retrying was the old workaround.
			 * It made the call return, but not with a usable table: the exchange
			 * then left through its early-exit path and reported -42023. Seen on
			 * a local build of the same image: pre-creating the table as an empty
			 * one lets the initialiser finish on the first try and the exchange
			 * proceeds to state 1 with a 354-byte request.
			 *
			 * The size and the pointer live at fixed image offsets, so they can
			 * be filled in before the call. */
			{
				uint64_t table = guest_alloc(64 * 4);
				uint8_t zeroes[64 * 4];
				memset(zeroes, 0, sizeof(zeroes));
				uc_mem_write(uc, table, zeroes, sizeof(zeroes));
				uint32_t table_size = 64;
				uc_mem_write(uc, g_base + 0x2bc874, &table_size, 4);
				uc_mem_write(uc, g_base + 0x2bbea0, &table, 8);
				append(out, cap, &used,
				       "[X64] pre-created hash table at %#llx (size %u)\n",
				       (unsigned long long)table, table_size);
			}

			uc_reg_write(uc, UC_X86_REG_RDI, &context_slot);
			uc_reg_write(uc, UC_X86_REG_RSI, &hardware_addr);
			append(out, cap, &used, "[X64] calling %s(ctx=%#llx, hw=%#llx)\n",
			       entries[e].name, (unsigned long long)context_slot,
			       (unsigned long long)hardware_addr);
		}

		if (e == 0) {
			uint8_t prologue[16];
			if (uc_mem_read(uc, where, prologue, sizeof(prologue)) == UC_ERR_OK) {
				append(out, cap, &used, "[X64] bytes at %s:", entries[e].name);
				for (size_t i = 0; i < sizeof(prologue); i++) append(out, cap, &used, " %02x", prologue[i]);
				append(out, cap, &used, "\n");
			}
		}

		uint32_t calls = 0;

		/* The exchange result, kept where the summary line can reach it. The
		 * replay of a late initialiser overwrites rax, and the summary used to
		 * report that clobbered value - printing OK for a call that had
		 * returned 0x10000600. */
		uint64_t exchange_final = 0;
		int exchange_reported = 0;

		/* Everything from here on belongs to the driver modes; mode 0 is the
		 * zero-argument survey and must not go through the initialisation
		 * sequence at all. */
		if (mode >= 1) {
			/* A single long run only says "timed out". Slicing it does better:
			 * each slice ends on a small budget, the program counter is read
			 * between slices, and the addresses that recur identify the loop
			 * the guest is stuck in. Without that, a timeout is a dead end. */
			uint64_t hot_addr[6] = {0};
			int hot_count[6] = {0};
			int hot_distinct = 0;
			uint32_t slices = 0;
			uint64_t at = where;
			(void)at;

			/* The survey used to run the entry forty times to find the loop it
			 * was stuck in. That was a diagnostic for a call that never
			 * returned; now that the entry does return, running it with no
			 * stack, no arguments and no return address builds a context and
			 * then throws it away, forty times over.
			 *
			 * A local run of the same image initialises once and exchanges
			 * successfully. Anything more than one call is the difference
			 * between here and there, so the survey is off. */
			err = UC_ERR_OK;
			for (int s = 0; s < 0; s++) {
				ctx.msg_pending = 0;

				err = uc_emu_start(uc, at, 0, 50000, 2000000);
				uint64_t rip = 0;
				uc_reg_read(uc, UC_X86_REG_RIP, &rip);
				slices++;

				/* A message send was requested. Resolve it here, at top level,
				 * because the method's implementation is guest code and calling
				 * it from inside the hook would re-enter the engine.
				 *
				 * The call left its return address on the guest stack, so after
				 * the method returns, execution resumes at msg_resume with rax
				 * holding the result - exactly what the caller expects. */
				if (ctx.msg_pending) {
					uint64_t isa = 0;
					const char *reason = NULL;
					uint64_t imp = 0;

					if (ctx.msg_receiver != 0 &&
					    uc_mem_read(uc, ctx.msg_receiver, &isa, 8) == UC_ERR_OK) {
						imp = objc_lookup(isa, ctx.msg_selector, &reason);
						if (imp == 0) {
							/* Say what was actually asked for. The receiver
							 * and its isa are the two facts that separate "the
							 * guest built an object we do not know" from "the
							 * selector is not on that class". */
							append(out, cap, &used,
							       "[X64] msgSend miss: recv=%#llx isa=%#llx sel=%#llx\n",
							       (unsigned long long)ctx.msg_receiver,
							       (unsigned long long)isa,
							       (unsigned long long)ctx.msg_selector);
						}
					} else {
						reason = "receiver unreadable";
						append(out, cap, &used,
						       "[X64] msgSend unreadable receiver %#llx sel=%#llx\n",
						       (unsigned long long)ctx.msg_receiver,
						       (unsigned long long)ctx.msg_selector);
					}

					if (imp == 0) {
						ctx.objc_misses++;
						snprintf(ctx.objc_last_miss, sizeof(ctx.objc_last_miss),
						         "%s", reason ? reason : "unknown");
						append(out, cap, &used,
						       "[X64] msgSend unresolved: %s (receiver=%#llx)\n",
						       ctx.objc_last_miss,
						       (unsigned long long)ctx.msg_receiver);
						break;
					}

					/* Run the method with the caller's own arguments. Its
					 * return address is already on the stack, so the method
					 * returns straight to msg_resume. */
					uint64_t method_args[8] = { 0 };
					uint64_t rdi = 0, rsi = 0, rdx = 0, rcx = 0, r8v = 0, r9v = 0;
					uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
					uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
					uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
					uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
					uc_reg_read(uc, UC_X86_REG_R8, &r8v);
					uc_reg_read(uc, UC_X86_REG_R9, &r9v);
					method_args[0] = rdi; method_args[1] = rsi; method_args[2] = rdx;
					method_args[3] = rcx; method_args[4] = r8v; method_args[5] = r9v;

					uint64_t result = 0;
					uc_err merr = call_guest_n(uc, g_base + imp,
					                           g_stack_base + 0x100000,
					                           trampoline, method_args, 6, &result);
					ctx.objc_sends++;

					if (merr != UC_ERR_OK) {
						append(out, cap, &used,
						       "[X64] msgSend method faulted err=%u\n", merr);
						break;
					}

					/* Put the result where the caller reads it and continue at
					 * the instruction after the call. */
					set_rax(uc, result);
					at = ctx.msg_resume;
					continue;
				}

				int found = -1;
				for (int k = 0; k < hot_distinct; k++) {
					if (hot_addr[k] == rip) { found = k; break; }
				}
				if (found >= 0) {
					hot_count[found]++;
				} else if (hot_distinct < 6) {
					hot_addr[hot_distinct] = rip;
					hot_count[hot_distinct] = 1;
					hot_distinct++;
				}

				/* Unicorn 2.1 has no timeout status: a long run either runs
				 * out of its instruction budget and returns OK, or fails with
				 * a real error. Either way another slice is pointless. */
				if (err != UC_ERR_OK) {
					break;
				}
				at = rip;
			}

			calls = ctx.served_total - before;
			append(out, cap, &used, "[X64] %-22s slices=%u last_err=%u (%u calls)\n",
			       entries[e].name, slices, err, calls);
			for (int k = 0; k < hot_distinct; k++) {
				append(out, cap, &used, "[X64]   hot rip=%#llx seen=%d\n",
				       (unsigned long long)hot_addr[k], hot_count[k]);
			}

			/* The initialisers pthread_once asked for, run for real. Skipping
			 * them left a global at zero and the first 32-bit divide raised
			 * #DE, which is what ended the previous run. */
			for (int k = 0; k < ctx.once_count; k++) {
				uint64_t once_rax = 0;
				uc_err once_err = call_guest(uc, ctx.once_inits[k],
				                             g_stack_base + 0x100000,
				                             trampoline, &once_rax);
				append(out, cap, &used,
				       "[X64] ran once-init %#llx err=%u rax=%#llx\n",
				       (unsigned long long)ctx.once_inits[k], once_err,
				       (unsigned long long)once_rax);
			}

			{
				uint64_t zero = 0;
				uc_reg_write(uc, UC_X86_REG_RAX, &zero);
				uc_reg_write(uc, UC_X86_REG_RDX, &zero);
				uc_reg_write(uc, UC_X86_REG_RSI, &hardware_addr);
				uc_reg_write(uc, UC_X86_REG_RDI, &context_slot);
				uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

				/* The retry must be checked the same way as any other call.
				 * It used to run with no return address and a three-million
				 * instruction budget, which reports success when the budget
				 * runs out - so "err=0" here never meant the initialiser had
				 * finished. */
				uint64_t retry_args[2] = { context_slot, hardware_addr };
				uint64_t retry_rax = 0;
				err = call_guest_n(uc, where, g_stack_base + 0x100000,
				                   trampoline, retry_args, 2, &retry_rax);
				append(out, cap, &used,
				       "[X64] retry after once-inits: err=%u rax=%#llx (%u calls)\n",
				       err, (unsigned long long)retry_rax, ctx.served_total);
				if (err != UC_ERR_OK) {
					uint64_t stop = 0;
					uc_reg_read(uc, UC_X86_REG_RIP, &stop);
					append(out, cap, &used,
					       "[X64]   initialiser stopped at %#llx (image+%#llx), fault kind=%d addr=%#llx\n",
					       (unsigned long long)stop,
					       (unsigned long long)(stop >= g_base ? stop - g_base : 0),
					       ctx.fault_kind, (unsigned long long)ctx.fault_addr);
				}
			}

			/* mode 2 continues into the exchange step. Eight arguments, so the
			 * last two travel on the stack; the field it writes doubles as an
			 * output pointer and a length, which is why both are read back. */
			if (mode >= 2 && context_slot != 0) {
				uint64_t exchange_addr = 0;
				uint64_t sign_addr = 0;
				for (uint32_t q = 0; q < entry_count; q++) {
					if (strcmp(entries[q].name, "_Mib5yocT") == 0) {
						exchange_addr = g_base + entries[q].addr;
					}
					if (strcmp(entries[q].name, "_Fc3vhtJDvr") == 0) {
						sign_addr = g_base + entries[q].addr;
					}
				}

				if (exchange_addr == 0) {
					append(out, cap, &used, "[X64] no _Mib5yocT in this image\n");
				} else {
					uint64_t context_value = 0;
					uc_mem_read(uc, context_slot, &context_value, 8);

					/* The exchange input for the first leg is the SAP setup
					 * certificate, not a server challenge: the certificate is
					 * fetched over HTTPS, fed to the guest, and the guest's
					 * output is what gets posted to the setup endpoint. An
					 * empty input can only ever produce an empty result. */
					uint64_t input_addr = guest_alloc(SAP_SETUP_CERT_LEN);
					uint64_t out_field = guest_alloc(8);
					uint64_t len_field = guest_alloc(8);
					uint64_t res_field = guest_alloc(4);
					uint64_t zero = 0;
					uint32_t zero32 = 0;
					uc_mem_write(uc, input_addr, sap_setup_cert, SAP_SETUP_CERT_LEN);
					uc_mem_write(uc, out_field, &zero, 8);
					uc_mem_write(uc, len_field, &zero, 8);
					uc_mem_write(uc, res_field, &zero32, 4);

					uint64_t args[8] = {
						200, hardware_addr, context_value, input_addr,
						SAP_SETUP_CERT_LEN, out_field, len_field, res_field,
					};

					/* Replaying the late initialisers did not change the status at
					 * all, so that theory is dead. What has not been varied yet is
					 * the protocol version: this is a 2013 binary and 200 is what
					 * the 2026 bag advertises, which it may simply not speak. The
					 * sweep below reports the status for each candidate. */
					uint64_t exchange_status = 0;
					uc_err xerr = UC_ERR_OK;
					uint64_t out_ptr = 0, out_len = 0;
					uint32_t result_code = 0;



					/* 200 is the only version the binary accepts: 3, 2, 1 and 0
					 * all return the same -42091, while 200 takes a different
					 * path. The sweep was worth running once; it is not worth
					 * repeating on every probe. */
					static const uint64_t candidate_versions[] = {200};

					for (size_t v = 0;
					     v < sizeof(candidate_versions) / sizeof(candidate_versions[0]);
					     v++) {
						args[0] = candidate_versions[v];

						/* Captured before the call: anything registered during it
						 * is what the replay loop below has to run. Taking the
						 * count afterwards made the loop a no-op. */
						int before_count = ctx.once_count;

						xerr = call_guest_n(uc, exchange_addr,
						                    g_stack_base + 0x100000,
						                    trampoline, args, 8,
						                    &exchange_status);

						out_ptr = 0; out_len = 0; result_code = 0;
						uc_mem_read(uc, out_field, &out_ptr, 8);
						uc_mem_read(uc, len_field, &out_len, 8);
						uc_mem_read(uc, res_field, &result_code, 4);

						exchange_final = exchange_status;
						exchange_reported = 1;

						if (xerr != UC_ERR_OK) {
							uint64_t stop_rip = 0;
							uc_reg_read(uc, UC_X86_REG_RIP, &stop_rip);
							append(out, cap, &used,
							       "[X64] exchange stopped: err=%u rip=%#llx (image+%#llx)\n",
							       xerr, (unsigned long long)stop_rip,
							       (unsigned long long)(stop_rip >= g_base ? stop_rip - g_base : 0));
							append(out, cap, &used,
							       "[X64]   last fault: kind=%d addr=%#llx\n",
							       ctx.fault_kind, (unsigned long long)ctx.fault_addr);
						}

						append(out, cap, &used,
						       "[X64] exchange: version=%llu in=%u err=%u status=%lld state=%u outlen=%llu\n",
						       (unsigned long long)candidate_versions[v],
						       SAP_SETUP_CERT_LEN, xerr,
						       (long long)(int32_t)exchange_status, result_code,
						       (unsigned long long)out_len);
						append(out, cap, &used,
						       "[X64]   expected state 1 after the certificate leg and 0 after "
						       "the server reply; status must be 0\n");

						/* First leg succeeded: hand the request to the app, feed the
						 * reply back, then sign. Only runs when the app installed a
						 * callback; without one this build behaves as before. */
						if ((int32_t)exchange_status == 0 && result_code == 1 &&
						    out_len > 0 && out_len <= 8192 && g_sap_post != 0) {
							uint8_t request[8192];
							uint8_t reply[24576];
							size_t reply_len = 0;
							if (uc_mem_read(uc, out_ptr, request, (size_t)out_len) != UC_ERR_OK) {
								append(out, cap, &used, "[X64] sap: cannot read request\n");
							} else {
								int rc = g_sap_post(request, (size_t)out_len,
								                    reply, sizeof(reply), &reply_len);
								append(out, cap, &used,
								       "[X64] sap: post rc=%d reply=%zu\n", rc, reply_len);
								if (g_sap_note[0] != 0) {
									append(out, cap, &used,
									       "[X64] sap: note=%s\n", g_sap_note);
								}
								if (rc == 0 && reply_len > 0) {
									uint64_t zero = 0;
									uint32_t zero4 = 0;
									uint64_t reply_addr = guest_alloc(reply_len);
									uc_err werr = uc_mem_write(uc, reply_addr, reply, reply_len);

									/* What the guest will actually read, read back
									 * from its own memory. The app reports what it
									 * decoded; this reports what landed. They can
									 * differ, and the library answers the first
									 * byte being wrong with a code that appears
									 * nowhere in the binary as a constant. */
									uint8_t back[16];
									uc_err rerr = uc_mem_read(uc, reply_addr, back, 16);
									append(out, cap, &used,
									       "[X64] sap: guest reply w=%u r=%u addr=%#llx head=",
									       werr, rerr, (unsigned long long)reply_addr);
									for (int i = 0; i < 16; i++) {
										append(out, cap, &used, "%02x", back[i]);
									}
									append(out, cap, &used, "\n");
									uint64_t out2 = guest_alloc(8);
									uint64_t len2 = guest_alloc(8);
									uint64_t res2 = guest_alloc(4);
									uc_mem_write(uc, out2, &zero, 8);
									uc_mem_write(uc, len2, &zero, 8);
									uc_mem_write(uc, res2, &zero4, 4);

									uint64_t args2[8] = { args[0], hardware_addr, context_slot,
									                     reply_addr, reply_len,
									                     out2, len2, res2 };
									uint64_t st2 = 0;
									uc_err e2 = call_guest_n(uc, exchange_addr,
									                        g_stack_base + 0x100000,
									                        trampoline, args2, 8, &st2);
									uint64_t o2 = 0, l2 = 0;
									uint32_t s2 = 0;
									uc_mem_read(uc, out2, &o2, 8);
									uc_mem_read(uc, len2, &l2, 8);
									uc_mem_read(uc, res2, &s2, 4);
									append(out, cap, &used,
									       "[X64] sap: exchange2 err=%u status=%lld state=%u outlen=%llu\n",
									       e2, (long long)(int32_t)st2, s2,
									       (unsigned long long)l2);

									/* The second exchange consumes the server's
									 * reply; the condition the reference checks is
									 * that state comes back 0. Its status is not
									 * part of the contract - a non-zero status here
									 * still means the reply was processed. Gating on
									 * it skipped the signature entirely. */
									if (e2 == UC_ERR_OK && s2 == 0 &&
									    sign_addr != 0) {
										uint64_t sig_out = guest_alloc(8);
										uint64_t sig_len = guest_alloc(8);
										uc_mem_write(uc, sig_out, &zero, 8);
										uc_mem_write(uc, sig_len, &zero, 8);
										uint64_t sargs[5] = { context_slot, reply_addr,
										                      reply_len, sig_out, sig_len };
										uint64_t st3 = 0;
										uc_err e3 = call_guest_n(uc, sign_addr,
										                        g_stack_base + 0x100000,
										                        trampoline, sargs, 5, &st3);
										uint64_t so = 0, sl = 0;
										uc_mem_read(uc, sig_out, &so, 8);
										uc_mem_read(uc, sig_len, &sl, 8);
										append(out, cap, &used,
										       "[X64] sap: sign err=%u status=%lld len=%llu\n",
										       e3, (long long)(int32_t)st3,
										       (unsigned long long)sl);
										if (e3 == UC_ERR_OK && (int32_t)st3 == 0 &&
										    so != 0 && sl > 0 && sl <= 4096) {
											uint8_t sig[4096];
											if (uc_mem_read(uc, so, sig, (size_t)sl) == UC_ERR_OK) {
												append(out, cap, &used,
												       "[X64] sap: signature=");
												for (uint64_t i = 0; i < sl; i++) {
													append(out, cap, &used, "%02x", sig[i]);
												}
												append(out, cap, &used, "\n");
											}
										}
									}
								}
							}
							break;
						}

						/* Any initialiser the call registered is replayed before
						 * the next attempt, so the sweep does not just repeat the
						 * same incomplete state five times. */
						for (int k = before_count; k < ctx.once_count && k < 8; k++) {
							uint64_t once_rax = 0;
							call_guest(uc, ctx.once_inits[k], g_stack_base + 0x100000,
							           trampoline, &once_rax);
						}
					}

					/* Every field dumped raw. Reading only the three that were
					 * guessed to matter hid the possibility that the call writes
					 * somewhere else entirely, or that a field is narrower than
					 * the eight bytes read from it. */
					uint8_t raw[32];
					if (uc_mem_read(uc, out_field, raw, 32) == UC_ERR_OK) {
						append(out, cap, &used, "[X64] raw out_field..+32:");
						for (int i = 0; i < 32; i++) {
							append(out, cap, &used, " %02x", raw[i]);
						}
						append(out, cap, &used, "\n");
					}

					/* The return value is int32_t to the caller, but reading the
					 * whole rax shows whether the upper half carries anything. */
					append(out, cap, &used,
					       "[X64] status raw rax=%#llx as i32=%lld as u32=%lu\n",
					       (unsigned long long)exchange_status,
					       (long long)(int32_t)(uint32_t)exchange_status,
					       (unsigned long)(uint32_t)exchange_status);

					append(out, cap, &used, "[X64] exchange out=%#llx len=%llu\n",
					       (unsigned long long)out_ptr, (unsigned long long)out_len);

					/* If the return value looks like an address inside the image
					 * rather than a small status code, read what it points at.
					 * A pointer to a message would name the failure outright,
					 * and that is worth more than another round of guessing at
					 * which shim is wrong. */
					if (exchange_status >= g_base && exchange_status < g_base + code_span) {
						uint8_t text_at[96];
						memset(text_at, 0, sizeof(text_at));
						if (uc_mem_read(uc, exchange_status, text_at, sizeof(text_at) - 1) == UC_ERR_OK) {
							append(out, cap, &used, "[X64] rax points into image (+%#llx):\n",
							       (unsigned long long)(exchange_status - g_base));
							append(out, cap, &used, "[X64]   hex:");
							for (size_t i = 0; i < 48; i++) {
								append(out, cap, &used, " %02x", text_at[i]);
							}
							append(out, cap, &used, "\n[X64]   ascii: ");
							for (size_t i = 0; i < 48; i++) {
								uint8_t ch = text_at[i];
								append(out, cap, &used, "%c",
								       (ch >= 0x20 && ch < 0x7f) ? (char)ch : '.');
							}
							append(out, cap, &used, "\n");
						}
					}

					if (out_ptr != 0 && out_len > 0 && out_len < 4096) {
						uint8_t dump[48];
						size_t take = out_len < sizeof(dump) ? (size_t)out_len : sizeof(dump);
						if (uc_mem_read(uc, out_ptr, dump, take) == UC_ERR_OK) {
							append(out, cap, &used, "[X64] output:");
							for (size_t i = 0; i < take; i++) {
								append(out, cap, &used, " %02x", dump[i]);
							}
							append(out, cap, &used, "\n");
						}
					}
				}
			}
		} else {
			err = uc_emu_start(uc, where, 0, 1500000, 5000000);
			calls = ctx.served_total - before;
		}

		/* mode 1 already reported per slice; the generic branches below would
		 * describe a timeout as "completed", so they are skipped for it. */
		if (mode == 0 && ctx.hit_slot >= 0) {
			append(out, cap, &used, "[X64] %-22s UNIMPLEMENTED %s (%u calls)\n",
			       entries[e].name, import_names[ctx.hit_slot], calls);
		} else if (mode == 0 && err == UC_ERR_OK) {
			append(out, cap, &used, "[X64] %-22s completed (%u calls)\n", entries[e].name, calls);
		} else if (mode == 0) {
			uint64_t rip = 0; uc_reg_read(uc, UC_X86_REG_RIP, &rip);
			append(out, cap, &used, "[X64] %-22s err=%u rip=%#llx fault=%#llx (%u calls)\n",
			       entries[e].name, err, (unsigned long long)rip,
			       (unsigned long long)ctx.fault_addr, calls);
		}

		if (mode >= 1) {
			uint64_t status = 0, context_value = 0;
			if (exchange_reported) {
				status = exchange_final;
			} else {
				uc_reg_read(uc, UC_X86_REG_RAX, &status);
			}
			if (context_slot != 0) {
				uc_mem_read(uc, context_slot, &context_value, 8);
			}
			append(out, cap, &used, "[X64] status=%lld context=%#llx %s\n",
			       (long long)(int32_t)status, (unsigned long long)context_value,
			       (int32_t)status == 0 && context_value != 0 ? "OK" : "NOT READY");

			for (int k = 0; k < ctx.sysctl_count; k++) {
				append(out, cap, &used, "[X64] sysctl asked: %s (answered -1)\n",
				       ctx.sysctl_names[k]);
			}

			if (ctx.sysctl_count > 0) {
				append(out, cap, &used, "[X64] sysctl keys:");
				for (int k = 0; k < ctx.sysctl_count; k++) {
					append(out, cap, &used, " %s", ctx.sysctl_names[k]);
				}
				append(out, cap, &used, "\n");
			}

			if (ctx.syscall_seen) {
				append(out, cap, &used, "[X64] syscall #%llu reached\n",
				       (unsigned long long)ctx.syscall_nr);
			}

			/* Which imports actually ran, in the order they were first hit.
			 * Without this a missing objc_msgSend looks the same whether the
			 * code path was never taken or the call was answered silently. */
			/* Which pages of the image were executed. Printed as ranges so
			 * the shape of the taken path is visible at a glance. */
			if (ctx.code_pages != NULL) {
				uint64_t executed = 0;
				for (uint64_t i = 0; i < ctx.code_pages_count; i++) {
					if (ctx.code_pages[i >> 3] & (1u << (i & 7))) {
						executed++;
					}
				}
				append(out, cap, &used,
				       "[X64] code coverage: %llu of %llu pages (%llu bytes)\n",
				       (unsigned long long)executed,
				       (unsigned long long)ctx.code_pages_count,
				       (unsigned long long)(executed * 4096));

				int shown = 0;
				uint64_t run_start = 0;
				int in_run = 0;
				for (uint64_t i = 0; i <= ctx.code_pages_count; i++) {
					int hit = (i < ctx.code_pages_count) &&
					          (ctx.code_pages[i >> 3] & (1u << (i & 7)));
					if (hit && !in_run) {
						run_start = i;
						in_run = 1;
					} else if (!hit && in_run) {
						if (shown < 12) {
							append(out, cap, &used,
							       "[X64]   executed %#llx..%#llx\n",
							       (unsigned long long)(run_start << 12),
							       (unsigned long long)(i << 12));
							shown++;
						}
						in_run = 0;
					}
				}
			}

			append(out, cap, &used, "[X64] export entry hits:");
			for (int i = 0; i < ctx.entry_count; i++) {
				append(out, cap, &used, " %s=%u", entries[i].name, ctx.entry_hits[i]);
			}
			append(out, cap, &used, "\n");

			/* Dispatch stops the guest when it has no handler, so the slot it
			 * stopped on is the name of the missing implementation. Printing it
			 * saves decoding a stub address by hand. */
			if (ctx.hit_slot >= 0 && (uint32_t)ctx.hit_slot < ctx.stub_count) {
				append(out, cap, &used,
				       "[X64] stopped on unhandled import: %s (slot %d)\n",
				       import_names[ctx.hit_slot], ctx.hit_slot);
			}

			append(out, cap, &used, "[X64] stubs hit (%d distinct):", ctx.visited_count);
			for (int i = 0; i < ctx.visited_count; i++) {
				append(out, cap, &used, " %s", import_names[ctx.visited[i]]);
			}
			append(out, cap, &used, "\n");

			/* Dump the context object whole. Guessing which offset holds the
			 * status produced two wrong answers in a row; one hexdump shows
			 * every field it actually populated. The struct is a few hundred
			 * bytes and the object is heap-allocated, so reading 0x400 from its
			 * base stays inside the allocation we handed out. */
			if (mode >= 2 && context_slot != 0) {
				uint64_t context_value = 0;
				if (uc_mem_read(uc, context_slot, &context_value, 8) == UC_ERR_OK &&
				    context_value != 0) {
					append(out, cap, &used,
					       "[X64] context dump at %#llx:\n",
					       (unsigned long long)context_value);
					for (int row = 0; row < 0x40; row++) {
						uint64_t base_row = context_value + (uint64_t)row * 16;
						uint64_t word[2] = { 0, 0 };
						if (uc_mem_read(uc, base_row, word, 16) != UC_ERR_OK) {
							break;
						}
						/* Only rows that hold something are worth printing;
						 * an empty context is mostly zeros. */
						if (word[0] == 0 && word[1] == 0) {
							continue;
						}
						append(out, cap, &used, "[X64]   +%03x: %016llx %016llx\n",
						       row * 16,
						       (unsigned long long)word[0],
						       (unsigned long long)word[1]);
					}
				}
			}

			if (ctx.vm_state_count > 0) {
				append(out, cap, &used, "[X64] vm states seen (%d):",
				       ctx.vm_state_count);
				for (int i = 0; i < ctx.vm_state_count && i < 64; i++) {
					append(out, cap, &used, " %u", ctx.vm_states[i]);
				}
				append(out, cap, &used, "\n");
			}

			if (ctx.objc_sends > 0 || ctx.objc_misses > 0) {
				append(out, cap, &used,
				       "[X64] objc: %d sends served, %d misses (last: %s)\n",
				       ctx.objc_sends, ctx.objc_misses,
				       ctx.objc_last_miss[0] ? ctx.objc_last_miss : "none");
			}

			for (int k = 0; k < ctx.once_count; k++) {
				append(out, cap, &used, "[X64] once-init ran in place: %#llx\n",
				       (unsigned long long)ctx.once_inits[k]);
			}
		}
	}

	append(out, cap, &used, "[X64] exchange pc trace (%d):", ctx.pc_count);
	for (int i = 0; i < ctx.pc_count && i < 160; i++) {
		append(out, cap, &used, " %x", ctx.pc_trace[i]);
	}
	append(out, cap, &used, "\n");
	append(out, cap, &used,
	       "[X64] whiten loop: entries=%llu rcx=%#llx rsi=%#llx\n",
	       (unsigned long long)ctx.loop_hits,
	       (unsigned long long)ctx.loop_rcx,
	       (unsigned long long)ctx.loop_rsi);
	append(out, cap, &used, "[X64] pc block sigs (%llu blocks of 4096):",
	       (unsigned long long)((ctx.pc_total + 4095) >> 12));
	for (uint32_t b = 0; b < 64 && b < (ctx.pc_total + 4095) >> 12; b++) {
		append(out, cap, &used, " %x", ctx.pc_block[b]);
	}
	append(out, cap, &used, "\n");
	{
		uint64_t total = ctx.pc_total;
		uint64_t start = total > 256 ? total - 256 : 0;
		append(out, cap, &used, "[X64] exchange pc last (%llu):",
		       (unsigned long long)total);
		for (uint64_t i = start; i < total; i++) {
			append(out, cap, &used, " %x", ctx.pc_last[i % 256]);
		}
		append(out, cap, &used, "\n");
	}
	append(out, cap, &used, "[X64] shim trace: %s\n",
	       ctx.shim_trace_len ? ctx.shim_trace : "(none)");
	append(out, cap, &used, "[X64] call order: %s\n",
	       ctx.call_trace_len ? ctx.call_trace : "(none)");
	append(out, cap, &used, "[X64] imports served: %u calls across", ctx.served_total);
	int distinct = 0;
	for (uint32_t i = 0; i < import_count; i++) if (served[i] > 0) distinct++;
	append(out, cap, &used, " %d imports\n", distinct);
	int shown = 0;
	for (uint32_t i = 0; i < import_count && shown < 14; i++) {
		if (served[i] == 0) continue;
		append(out, cap, &used, "[X64]   %-28s %u\n", import_names[i], served[i]);
		shown++;
	}

	uc_close(uc);
	free(blob);
}
