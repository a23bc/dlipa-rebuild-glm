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

#define MAX_IMPORTS 320
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
	if (strncmp(name, "_pthread_mutex_", 15) == 0 ||
	    strncmp(name, "_pthread_rwlock_", 16) == 0 ||
	    strncmp(name, "_os_unfair_lock_", 16) == 0 ||
	    strcmp(name, "_pthread_once") == 0) {
		/* Single-threaded guest: locks are always uncontended. pthread_once
		 * would normally call its init function; skipped for now. */
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

static void on_bad_fetch(uc_engine *uc, uint64_t address, int size, void *user)
{
	(void)uc; (void)size;
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	ctx->fault_addr = address; ctx->fault_kind = 3;
}

void x64probe_report(const char *path, char *out, size_t cap)
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

	uc_hook hook, h1, h2, h3;
	uc_hook_add(uc, &hook, UC_HOOK_CODE, on_code, &ctx,
	            g_stub_base, g_stub_base + (uint64_t)stub_count * STUB_SLOT - 1);
	uc_hook_add(uc, &h1, UC_HOOK_MEM_READ_UNMAPPED, on_bad_read, &ctx, 1, 0);
	uc_hook_add(uc, &h2, UC_HOOK_MEM_WRITE_UNMAPPED, on_bad_write, &ctx, 1, 0);
	uc_hook_add(uc, &h3, UC_HOOK_MEM_FETCH_UNMAPPED, on_bad_fetch, &ctx, 1, 0);

	uint64_t start = g_base + entries[0].addr;
	uint8_t prologue[24];
	if (uc_mem_read(uc, start, prologue, sizeof(prologue)) == UC_ERR_OK) {
		append(out, cap, &used, "[X64] bytes at entry:");
		for (size_t i = 0; i < sizeof(prologue); i++) append(out, cap, &used, " %02x", prologue[i]);
		append(out, cap, &used, "\n");
	}

	append(out, cap, &used, "[X64] running %s\n", entries[0].name);
	err = uc_emu_start(uc, start, 0, 8000000, 40000000);

	if (ctx.hit_slot >= 0) {
		append(out, cap, &used, "[X64] stopped at unimplemented import [%d] %s\n",
		       ctx.hit_slot, import_names[ctx.hit_slot]);
	} else if (err == UC_ERR_OK) {
		append(out, cap, &used, "[X64] completed\n");
	} else {
		uint64_t rip = 0; uc_reg_read(uc, UC_X86_REG_RIP, &rip);
		append(out, cap, &used, "[X64] stopped: err=%u (%s) rip=%#llx\n", err, uc_strerror(err), (unsigned long long)rip);
		const char *kind = ctx.fault_kind == 1 ? "read" : ctx.fault_kind == 2 ? "write" : ctx.fault_kind == 3 ? "fetch" : "none";
		append(out, cap, &used, "[X64] fault=%s addr=%#llx\n", kind, (unsigned long long)ctx.fault_addr);
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
