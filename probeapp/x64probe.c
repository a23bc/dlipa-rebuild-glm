/* Stage 2b: place CoreFP where the emulator can run it.
 *
 * The binary is macOS x86-64 and nothing about it is loadable by iOS, so the
 * only way to execute it is to lay it out by hand. All the Mach-O reading -
 * segments, the 1004 rebases, the 103 binds, the export addresses - was done
 * offline by cmd/x86image, which emits a flat container precisely so this
 * file does not have to contain a Mach-O parser.
 *
 * What is left here is the part that genuinely needs the emulator: map the
 * segments at a chosen base, slide the interior pointers, point each bind at
 * a stub, and start executing.
 *
 * Milestone 1 deliberately stops at the first import call instead of trying
 * to serve it. A stub that returns without doing anything leaves RAX as
 * garbage and the guest wanders off into unmapped memory, which tells us
 * nothing. Stopping on entry to a stub says which import CoreFP reaches
 * first, and that is what the shims have to implement next. */

#include "x64probe.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#define MAX_IMPORTS 256
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

static uint32_t rd32(const uint8_t *p)
{
	uint32_t v;
	memcpy(&v, p, 4);
	return v;
}

static uint64_t rd64(const uint8_t *p)
{
	uint64_t v;
	memcpy(&v, p, 8);
	return v;
}

/* Constants and callbacks are data, not call targets: binding them to a stub
 * would hand the guest a pointer to executable bytes where it expects a CF
 * object. They get zeroed storage instead. */
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
	int hit_slot;
	uint64_t hit_pc;
	uint64_t fault_addr;
	int fault_kind;
} hook_ctx_t;

/* Captures where the guest went wrong instead of only that it did. "Invalid
 * memory read" with no address says nothing; the address, plus the instruction
 * that caused it, usually says everything. */
static void on_bad_read(uc_engine *uc, uc_mem_type type, uint64_t address,
                        int size, int64_t value, void *user)
{
	(void)uc; (void)type; (void)size; (void)value;
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	ctx->fault_addr = address;
	ctx->fault_kind = 1;
}

static void on_bad_write(uc_engine *uc, uc_mem_type type, uint64_t address,
                         int size, int64_t value, void *user)
{
	(void)uc; (void)type; (void)size; (void)value;
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	ctx->fault_addr = address;
	ctx->fault_kind = 2;
}

static void on_bad_fetch(uc_engine *uc, uint64_t address, int size, void *user)
{
	(void)uc; (void)size;
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	ctx->fault_addr = address;
	ctx->fault_kind = 3;
}

static void on_code(uc_engine *uc, uint64_t address, uint32_t size, void *user)
{
	hook_ctx_t *ctx = (hook_ctx_t *)user;
	if (address >= ctx->stub_base &&
	    address < ctx->stub_base + (uint64_t)ctx->stub_count * STUB_SLOT) {
		ctx->hit_slot = (int)((address - ctx->stub_base) / STUB_SLOT);
		ctx->hit_pc = address;
		uc_emu_stop(uc);
	}
}

void x64probe_report(const char *path, char *out, size_t cap)
{
	if (cap == 0) {
		return;
	}
	out[0] = 0;
	size_t used = 0;

	FILE *file = fopen(path, "rb");
	if (file == NULL) {
		append(out, cap, &used, "[X64] cannot open image: %s\n", path);
		return;
	}
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);

	uint8_t *blob = (uint8_t *)malloc((size_t)size);
	if (blob == NULL || fread(blob, 1, (size_t)size, file) != (size_t)size) {
		append(out, cap, &used, "[X64] short read\n");
		fclose(file);
		free(blob);
		return;
	}
	fclose(file);

	if (memcmp(blob, "X64I", 4) != 0 || rd32(blob + 4) != 1) {
		append(out, cap, &used, "[X64] bad magic or version\n");
		free(blob);
		return;
	}

	uint32_t seg_count = rd32(blob + 8);
	uint32_t import_count = rd32(blob + 12);
	uint32_t rebase_count = rd32(blob + 16);
	uint32_t bind_count = rd32(blob + 20);
	uint32_t entry_count = rd32(blob + 24);

	if (seg_count > MAX_SEGMENTS || import_count > MAX_IMPORTS || entry_count > MAX_ENTRIES) {
		append(out, cap, &used, "[X64] counts out of range\n");
		free(blob);
		return;
	}

	append(out, cap, &used,
	       "[X64] image: %u segments, %u imports, %u rebases, %u binds, %u entries\n",
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
	for (uint32_t i = 0; i < seg_count; i++) {
		segs[i].content = cursor;
		cursor += segs[i].content_len;
	}

	char import_names[MAX_IMPORTS][128];
	for (uint32_t i = 0; i < import_count; i++) {
		memcpy(import_names[i], cursor, 128);
		cursor += 128;
	}

	const uint8_t *rebase_data = cursor;
	cursor += (size_t)rebase_count * 8;

	const uint8_t *bind_data = cursor;
	cursor += (size_t)bind_count * 16;

	entry_t entries[MAX_ENTRIES];
	for (uint32_t i = 0; i < entry_count; i++) {
		memcpy(entries[i].name, cursor, 32);
		entries[i].addr = rd64(cursor + 32);
		cursor += 40;
	}

	/* Everything the image references lives at base + vmaddr, so pick a base
	 * far from the stack and the stub region. */
	const uint64_t base = 0x100000000ULL;
	const uint64_t stub_base = 0x700000000ULL;
	const uint64_t data_base = 0x710000000ULL;
	const uint64_t stack_base = 0x800000000ULL;
	const uint64_t stack_size = 0x100000ULL;

	uc_engine *uc = NULL;
	uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err != UC_ERR_OK) {
		append(out, cap, &used, "[X64] uc_open failed: %u\n", err);
		free(blob);
		return;
	}

	for (uint32_t i = 0; i < seg_count; i++) {
		err = uc_mem_map(uc, base + segs[i].vmaddr, (size_t)segs[i].vmsize, UC_PROT_ALL);
		if (err != UC_ERR_OK) {
			append(out, cap, &used, "[X64] map %s (%#llx) failed: %u\n",
			       segs[i].name, (unsigned long long)segs[i].vmsize, err);
			uc_close(uc);
			free(blob);
			return;
		}
		if (segs[i].content_len > 0) {
			err = uc_mem_write(uc, base + segs[i].vmaddr, segs[i].content, segs[i].content_len);
			if (err != UC_ERR_OK) {
				append(out, cap, &used, "[X64] write %s failed: %u\n", segs[i].name, err);
				uc_close(uc);
				free(blob);
				return;
			}
		}
	}
	append(out, cap, &used, "[X64] segments mapped at %#llx\n", (unsigned long long)base);

	/* Stub region: one slot per import, each a bare ret (0xC3 on x86-64).
	 *
	 * Unicorn rejects a mapping whose size is not a multiple of the host page,
	 * and 193 slots of 16 bytes is 3088 - so round up. The first version passed
	 * the raw size and the map failed with UC_ERR_ARG. */
	uint32_t stub_count = import_count;
	uint64_t stub_size = ((uint64_t)stub_count * STUB_SLOT + 0xfff) & ~0xfffULL;
	if (uc_mem_map(uc, stub_base, (size_t)stub_size, UC_PROT_ALL) != UC_ERR_OK) {
		append(out, cap, &used, "[X64] stub map failed (%llu bytes)\n",
		       (unsigned long long)stub_size);
		uc_close(uc);
		free(blob);
		return;
	}
	uint8_t stub_code[STUB_SLOT];
	memset(stub_code, 0xcc, sizeof(stub_code));
	stub_code[0] = 0xc3;
	for (uint32_t i = 0; i < stub_count; i++) {
		uc_mem_write(uc, stub_base + (uint64_t)i * STUB_SLOT, stub_code, STUB_SLOT);
	}

	uint32_t data_count = 0;
	for (uint32_t i = 0; i < import_count; i++) {
		if (is_data_import(import_names[i])) {
			data_count++;
		}
	}
	uint64_t data_size = ((uint64_t)data_count * DATA_SLOT + 0xfff) & ~0xfffULL;
	if (data_count > 0 &&
	    uc_mem_map(uc, data_base, (size_t)data_size, UC_PROT_ALL) != UC_ERR_OK) {
		append(out, cap, &used, "[X64] data map failed (%llu bytes)\n",
		       (unsigned long long)data_size);
		uc_close(uc);
		free(blob);
		return;
	}

	/* Rebases: the file stores link-time addresses, so add the slide. */
	for (uint32_t i = 0; i < rebase_count; i++) {
		uint64_t addr = rd64(rebase_data + (size_t)i * 8);
		uint64_t value = 0;
		if (uc_mem_read(uc, base + addr, &value, 8) != UC_ERR_OK) {
			continue;
		}
		value += base;
		uc_mem_write(uc, base + addr, &value, 8);
	}
	append(out, cap, &used, "[X64] applied %u rebases\n", rebase_count);

	/* Binds: each pointer slot aims at either a stub or zeroed data. */
	uint32_t data_cursor = 0;
	for (uint32_t i = 0; i < bind_count; i++) {
		const uint8_t *rec = bind_data + (size_t)i * 16;
		uint64_t addr = rd64(rec);
		uint32_t slot = rd32(rec + 8);
		int32_t addend = (int32_t)rd32(rec + 12);

		uint64_t target;
		if (slot < import_count && is_data_import(import_names[slot])) {
			target = data_base + (uint64_t)data_cursor * DATA_SLOT;
			data_cursor++;
		} else {
			target = stub_base + (uint64_t)slot * STUB_SLOT;
		}
		uint64_t value = target + (uint64_t)(int64_t)addend;
		uc_mem_write(uc, base + addr, &value, 8);
	}
	append(out, cap, &used, "[X64] applied %u binds\n", bind_count);

	if (uc_mem_map(uc, stack_base, (size_t)stack_size, UC_PROT_ALL) != UC_ERR_OK) {
		append(out, cap, &used, "[X64] stack map failed\n");
		uc_close(uc);
		free(blob);
		return;
	}
	uint64_t rsp = stack_base + stack_size - 0x100;
	uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

	for (uint32_t i = 0; i < entry_count; i++) {
		append(out, cap, &used, "[X64] entry %s = %#llx\n",
		       entries[i].name, (unsigned long long)(base + entries[i].addr));
	}

	if (entry_count == 0) {
		append(out, cap, &used, "[X64] no entries; stopping\n");
		uc_close(uc);
		free(blob);
		return;
	}

	/* Scoped to the stub region on purpose. A hook over the whole address
	 * space fires a callback per instruction, which at tens of millions of
	 * instructions is far slower than the emulation it is watching. */
	hook_ctx_t ctx = {0};
	ctx.uc = uc;
	ctx.stub_base = stub_base;
	ctx.stub_count = stub_count;
	ctx.hit_slot = -1;

	uc_hook hook;
	uc_hook_add(uc, &hook, UC_HOOK_CODE, on_code, &ctx,
	            stub_base, stub_base + (uint64_t)stub_count * STUB_SLOT - 1);

	uc_hook bad_read, bad_write, bad_fetch;
	uc_hook_add(uc, &bad_read, UC_HOOK_MEM_READ_UNMAPPED, on_bad_read, &ctx, 1, 0);
	uc_hook_add(uc, &bad_write, UC_HOOK_MEM_WRITE_UNMAPPED, on_bad_write, &ctx, 1, 0);
	uc_hook_add(uc, &bad_fetch, UC_HOOK_MEM_FETCH_UNMAPPED, on_bad_fetch, &ctx, 1, 0);

	uint64_t start = base + entries[0].addr;

	/* The prologue decides everything: an entry that loads a global first is a
	 * different kind of function from one that saves registers and returns. */
	uint8_t prologue[24];
	if (uc_mem_read(uc, start, prologue, sizeof(prologue)) == UC_ERR_OK) {
		append(out, cap, &used, "[X64] bytes at entry:");
		for (size_t i = 0; i < sizeof(prologue); i++) {
			append(out, cap, &used, " %02x", prologue[i]);
		}
		append(out, cap, &used, "\n");
	}

	append(out, cap, &used, "[X64] running %s for up to 20M instructions\n", entries[0].name);

	err = uc_emu_start(uc, start, 0, 5000000, 20000000);

	if (ctx.hit_slot >= 0) {
		append(out, cap, &used,
		       "[X64] stopped at import [%d] %s (first external call)\n",
		       ctx.hit_slot, ctx.hit_slot < (int)import_count ? import_names[ctx.hit_slot] : "?");
	} else if (err == UC_ERR_OK) {
		append(out, cap, &used, "[X64] completed without calling an import\n");
	} else {
		uint64_t rip = 0, rax = 0, rcx = 0, rdx = 0, rsi = 0, rdi = 0, rsp_now = 0;
		uc_reg_read(uc, UC_X86_REG_RIP, &rip);
		uc_reg_read(uc, UC_X86_REG_RAX, &rax);
		uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
		uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
		uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
		uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
		uc_reg_read(uc, UC_X86_REG_RSP, &rsp_now);

		append(out, cap, &used, "[X64] stopped: err=%u (%s) rip=%#llx\n",
		       err, uc_strerror(err), (unsigned long long)rip);
		append(out, cap, &used, "[X64] regs rax=%#llx rcx=%#llx rdx=%#llx rsi=%#llx rdi=%#llx rsp=%#llx\n",
		       (unsigned long long)rax, (unsigned long long)rcx,
		       (unsigned long long)rdx, (unsigned long long)rsi,
		       (unsigned long long)rdi, (unsigned long long)rsp_now);

		const char *kind = ctx.fault_kind == 1 ? "read" :
		                   ctx.fault_kind == 2 ? "write" :
		                   ctx.fault_kind == 3 ? "fetch" : "none";
		append(out, cap, &used, "[X64] fault=%s addr=%#llx (mapped: %s)\n",
		       kind, (unsigned long long)ctx.fault_addr,
		       ctx.fault_addr >= base && ctx.fault_addr < base + 0x2000000 ? "yes" : "no");
	}

	uc_close(uc);
	free(blob);
}
