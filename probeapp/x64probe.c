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

/* Returns 1 when the import was served, 0 when it has no handler. */
static int dispatch(hook_ctx_t *ctx, uint32_t slot)
{
	uc_engine *uc = ctx->uc;
	const char *name = ctx->names[slot];
	args_t a = read_args(uc);

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
		/* The initialiser is recorded, not called: invoking guest code from
		 * inside a hook means a re-entrant uc_emu_start, which is not worth
		 * the risk yet. The once word is marked done so the caller does not
		 * spin, and the report names what was skipped. */
		if (a.rsi != 0 && ctx->once_count < 8) {
			ctx->once_inits[ctx->once_count++] = a.rsi;
		}
		if (a.rdi != 0) {
			uint32_t done = 0xff;
			uc_mem_write(uc, a.rdi, &done, 4);
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

	if (strcmp(name, "_sysctlbyname") == 0 || strcmp(name, "_confstr") == 0) {
		/* Reporting failure is honest: these ask about the host, and the
		 * guest is not running on the host. */
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

	uc_err err = uc_emu_start(uc, fn, trampoline, 3000000, 0);
	if (err == UC_ERR_OK && out_rax != NULL) {
		uc_reg_read(uc, UC_X86_REG_RAX, out_rax);
	}
	return err;
}

static uc_err call_guest(uc_engine *uc, uint64_t fn, uint64_t stack_top,
                         uint64_t trampoline, uint64_t *out_rax)
{
	return call_guest_n(uc, fn, stack_top, trampoline, NULL, 0, out_rax);
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

	if (dispatch(ctx, slot)) {
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

	uc_hook hook, h1, h2, h3, h4;
	uc_hook_add(uc, &hook, UC_HOOK_CODE, on_code, &ctx,
	            g_stub_base, g_stub_base + (uint64_t)stub_count * STUB_SLOT - 1);
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
			uint32_t length = 20;
			uint8_t id[20];
			memset(id, 'A', sizeof(id));
			uc_mem_write(uc, hardware_addr, &length, 4);
			uc_mem_write(uc, hardware_addr + 4, id, sizeof(id));
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

		if (mode == 1) {
			/* A single long run only says "timed out". Slicing it does better:
			 * each slice ends on a small budget, the program counter is read
			 * between slices, and the addresses that recur identify the loop
			 * the guest is stuck in. Without that, a timeout is a dead end. */
			uint64_t hot_addr[6] = {0};
			int hot_count[6] = {0};
			int hot_distinct = 0;
			uint32_t slices = 0;
			uint64_t at = where;

			for (int s = 0; s < 40; s++) {
				err = uc_emu_start(uc, at, 0, 50000, 2000000);
				uint64_t rip = 0;
				uc_reg_read(uc, UC_X86_REG_RIP, &rip);
				slices++;

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

			if (ctx.once_count > 0) {
				uint64_t zero = 0;
				uc_reg_write(uc, UC_X86_REG_RAX, &zero);
				uc_reg_write(uc, UC_X86_REG_RDX, &zero);
				uc_reg_write(uc, UC_X86_REG_RSI, &hardware_addr);
				uc_reg_write(uc, UC_X86_REG_RDI, &context_slot);
				uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

				err = uc_emu_start(uc, where, 0, 3000000, 0);
				append(out, cap, &used,
				       "[X64] retry after once-inits: err=%u (%u calls)\n",
				       err, ctx.served_total);
			}

			/* mode 2 continues into the exchange step. Eight arguments, so the
			 * last two travel on the stack; the field it writes doubles as an
			 * output pointer and a length, which is why both are read back. */
			if (mode >= 2 && context_slot != 0) {
				uint64_t exchange_addr = 0;
				for (uint32_t q = 0; q < entry_count; q++) {
					if (strcmp(entries[q].name, "_Mib5yocT") == 0) {
						exchange_addr = g_base + entries[q].addr;
					}
				}

				if (exchange_addr == 0) {
					append(out, cap, &used, "[X64] no _Mib5yocT in this image\n");
				} else {
					uint64_t context_value = 0;
					uc_mem_read(uc, context_slot, &context_value, 8);

					uint64_t input_addr = guest_alloc(16);
					uint64_t out_field = guest_alloc(8);
					uint64_t len_field = guest_alloc(8);
					uint64_t res_field = guest_alloc(4);
					uint64_t zero = 0;
					uint32_t zero32 = 0;
					uc_mem_write(uc, input_addr, &zero, 8);
					uc_mem_write(uc, out_field, &zero, 8);
					uc_mem_write(uc, len_field, &zero, 8);
					uc_mem_write(uc, res_field, &zero32, 4);

					uint64_t args[8] = {
						200, hardware_addr, context_value, input_addr,
						0, out_field, len_field, res_field,
					};

					uint64_t exchange_status = 0;
					uc_err xerr = call_guest_n(uc, exchange_addr,
					                           g_stack_base + 0x100000,
					                           trampoline, args, 8,
					                           &exchange_status);

					uint64_t out_ptr = 0, out_len = 0;
					uint32_t result_code = 0;
					uc_mem_read(uc, out_field, &out_ptr, 8);
					uc_mem_read(uc, len_field, &out_len, 8);
					uc_mem_read(uc, res_field, &result_code, 4);

					append(out, cap, &used,
					       "[X64] exchange err=%u status=%lld result=%u out=%#llx len=%llu\n",
					       xerr, (long long)(int32_t)exchange_status, result_code,
					       (unsigned long long)out_ptr, (unsigned long long)out_len);

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
		if (mode != 1 && ctx.hit_slot >= 0) {
			append(out, cap, &used, "[X64] %-22s UNIMPLEMENTED %s (%u calls)\n",
			       entries[e].name, import_names[ctx.hit_slot], calls);
		} else if (mode != 1 && err == UC_ERR_OK) {
			append(out, cap, &used, "[X64] %-22s completed (%u calls)\n", entries[e].name, calls);
		} else if (mode != 1) {
			uint64_t rip = 0; uc_reg_read(uc, UC_X86_REG_RIP, &rip);
			append(out, cap, &used, "[X64] %-22s err=%u rip=%#llx fault=%#llx (%u calls)\n",
			       entries[e].name, err, (unsigned long long)rip,
			       (unsigned long long)ctx.fault_addr, calls);
		}

		if (mode >= 1) {
			uint64_t status = 0, context_value = 0;
			uc_reg_read(uc, UC_X86_REG_RAX, &status);
			if (context_slot != 0) {
				uc_mem_read(uc, context_slot, &context_value, 8);
			}
			append(out, cap, &used, "[X64] status=%lld context=%#llx %s\n",
			       (long long)(int32_t)status, (unsigned long long)context_value,
			       (int32_t)status == 0 && context_value != 0 ? "OK" : "NOT READY");

			if (ctx.syscall_seen) {
				append(out, cap, &used, "[X64] syscall #%llu reached\n",
				       (unsigned long long)ctx.syscall_nr);
			}

			for (int k = 0; k < ctx.once_count; k++) {
				append(out, cap, &used, "[X64] once-init not run: %#llx\n",
				       (unsigned long long)ctx.once_inits[k]);
			}
		}
	}

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
