/* Stage 1 of the TCI route: can this device interpret x86-64 at all?
 *
 * The claim under test is narrow and easy to falsify. The TCI build maps its
 * translation buffer PROT_READ|PROT_WRITE and never asks for PROT_EXEC, so an
 * emulator that runs here cannot have obtained executable memory - because
 * this app could not have obtained it either.
 *
 * So the report starts with a control: ask the kernel for exactly the memory
 * the JIT build would need and record what happens. If that fails and the
 * emulator still runs, the interpreter is doing its job.
 *
 * Nothing here touches Apple binaries. This is only about whether the CPU
 * model works on this device; SAP is a later question.
 */

#include "tciprobe.h"

#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

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

/* Positive control. This is precisely the allocation the JIT build needs,
 * so recording its outcome tells us what the interpreter had to avoid. */
static void report_exec_memory(char *out, size_t cap, size_t *used)
{
	size_t page = 0x4000;

	void *rw = mmap(NULL, page, PROT_READ | PROT_WRITE,
	                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rw == MAP_FAILED) {
		append(out, cap, used, "[TCI] control rw-only mmap: FAILED errno=%d\n", errno);
	} else {
		append(out, cap, used, "[TCI] control rw-only mmap: OK\n");
		munmap(rw, page);
	}

	errno = 0;
	void *rwx = mmap(NULL, page, PROT_READ | PROT_WRITE | PROT_EXEC,
	                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rwx == MAP_FAILED) {
		append(out, cap, used, "[TCI] control rwx mmap: FAILED errno=%d (why JIT cannot work)\n", errno);
	} else {
		append(out, cap, used, "[TCI] control rwx mmap: OK (unexpected on a jailed device)\n");
		munmap(rwx, page);
	}
}

/* Runs guest[0..len) and hands back the engine. `until` is the address just
 * past the last instruction, so execution ends without a terminating op. */
static uc_err run_guest(const uint8_t *code, size_t len, uint64_t base,
                        uc_engine **engine_out)
{
	uc_engine *uc = NULL;
	uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err != UC_ERR_OK) {
		return err;
	}

	err = uc_mem_map(uc, base, 0x4000, UC_PROT_ALL);
	if (err != UC_ERR_OK) {
		uc_close(uc);
		return err;
	}

	err = uc_mem_write(uc, base, code, len);
	if (err != UC_ERR_OK) {
		uc_close(uc);
		return err;
	}

	err = uc_emu_start(uc, base, base + len, 0, 0);
	if (err != UC_ERR_OK) {
		uc_close(uc);
		return err;
	}

	*engine_out = uc;
	return UC_ERR_OK;
}

static void report_arith(char *out, size_t cap, size_t *used)
{
	/* mov rax,7 ; mov rbx,5 ; add rax,rbx ; imul rax,rax,3 */
	static const uint8_t code[] = {
		0x48, 0xc7, 0xc0, 0x07, 0x00, 0x00, 0x00,
		0x48, 0xc7, 0xc3, 0x05, 0x00, 0x00, 0x00,
		0x48, 0x01, 0xd8,
		0x48, 0x6b, 0xc0, 0x03,
	};

	uc_engine *uc = NULL;
	uc_err err = run_guest(code, sizeof(code), 0x100000, &uc);
	if (err != UC_ERR_OK) {
		append(out, cap, used, "[TCI] arith: uc error %u (%s)\n", err, uc_strerror(err));
		return;
	}

	uint64_t rax = 0;
	uc_reg_read(uc, UC_X86_REG_RAX, &rax);
	uc_close(uc);

	append(out, cap, used, "[TCI] arith: rax=%llu expected=36 %s\n",
	       (unsigned long long)rax, rax == 36 ? "OK" : "MISMATCH");
}

static void report_div(char *out, size_t cap, size_t *used)
{
	/* mov rax,100 ; mov rcx,7 ; xor rdx,rdx ; div rcx
	 *
	 * Included on purpose: the TCI target declares no 64-bit divide, so the
	 * generic TCG layer expands it into a helper call. If that path were
	 * broken, this is the instruction that would show it. */
	static const uint8_t code[] = {
		0x48, 0xc7, 0xc0, 0x64, 0x00, 0x00, 0x00,
		0x48, 0xc7, 0xc1, 0x07, 0x00, 0x00, 0x00,
		0x48, 0x31, 0xd2,
		0x48, 0xf7, 0xf1,
	};

	uc_engine *uc = NULL;
	uc_err err = run_guest(code, sizeof(code), 0x200000, &uc);
	if (err != UC_ERR_OK) {
		append(out, cap, used, "[TCI] div: uc error %u (%s)\n", err, uc_strerror(err));
		return;
	}

	uint64_t rax = 0, rdx = 0;
	uc_reg_read(uc, UC_X86_REG_RAX, &rax);
	uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
	uc_close(uc);

	append(out, cap, used, "[TCI] div: rax=%llu rdx=%llu expected=14/2 %s\n",
	       (unsigned long long)rax, (unsigned long long)rdx,
	       (rax == 14 && rdx == 2) ? "OK" : "MISMATCH");
}

static void report_loop(char *out, size_t cap, size_t *used)
{
	/* mov rax,0 ; mov rcx,5 ; loop: inc rax ; dec rcx ; test rcx,rcx ; jne loop
	 *
	 * The displacement is 11 bytes back from the end of the jne, not 9: the
	 * jne itself is two bytes and the loop body starts at the first inc. An
	 * earlier version used -9, which landed inside the inc's encoding and
	 * executed an operand byte as an opcode. That was a bug in this test, not
	 * in the interpreter. */
	static const uint8_t code[] = {
		0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00,
		0x48, 0xc7, 0xc1, 0x05, 0x00, 0x00, 0x00,
		0x48, 0xff, 0xc0,
		0x48, 0xff, 0xc9,
		0x48, 0x85, 0xc9,
		0x75, 0xf5,
	};

	uc_engine *uc = NULL;
	uc_err err = run_guest(code, sizeof(code), 0x300000, &uc);
	if (err != UC_ERR_OK) {
		append(out, cap, used, "[TCI] loop: uc error %u (%s)\n", err, uc_strerror(err));
		return;
	}

	uint64_t rax = 0;
	uc_reg_read(uc, UC_X86_REG_RAX, &rax);
	uc_close(uc);

	append(out, cap, used, "[TCI] loop: rax=%llu expected=5 %s\n",
	       (unsigned long long)rax, rax == 5 ? "OK" : "MISMATCH");
}

void tciprobe_report(char *out, size_t cap)
{
	if (cap == 0) {
		return;
	}
	out[0] = 0;
	size_t used = 0;

	unsigned int major = 0, minor = 0;
	uc_version(&major, &minor);
	append(out, cap, &used, "[TCI] unicorn version %u.%u\n", major, minor);

	report_exec_memory(out, cap, &used);
	report_arith(out, cap, &used);
	report_div(out, cap, &used);
	report_loop(out, cap, &used);
}

/* Decisive follow-up to the control above.
 *
 * The control showed that an RWX mapping is granted on this device, which
 * contradicts what this project previously recorded (PROT_EXEC = EPERM).
 * A granted mapping is not the same as an executable one: iOS is known to
 * allow the mmap and then kill the process the moment the CPU jumps into an
 * unsigned page, because code signing is enforced at execution, not at
 * mapping.
 *
 * So this asks the only question that matters: emit a leaf function that
 * returns 42, flush the instruction cache, and call it. If it returns, JIT is
 * available here and the entire interpreter route is unnecessary. If the
 * process dies, the mapping was a decoy.
 *
 * Deliberately behind its own button: a refusal is a SIGKILL, and that would
 * take the rest of the report with it. */
void jitprobe_report(char *out, size_t cap)
{
	if (cap == 0) {
		return;
	}
	out[0] = 0;
	size_t used = 0;

	size_t page = 0x4000;
	uint8_t *p = mmap(NULL, page, PROT_READ | PROT_WRITE | PROT_EXEC,
	                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		append(out, cap, &used, "[JIT] mmap rwx: FAILED errno=%d\n", errno);
		return;
	}
	append(out, cap, &used, "[JIT] mmap rwx: OK\n");

	/* mov w0, #42 ; ret */
	static const uint8_t code[] = {
		0x40, 0x05, 0x80, 0x52,
		0xc0, 0x03, 0x5f, 0xd6,
	};
	memcpy(p, code, sizeof(code));
	sys_icache_invalidate(p, page);

	append(out, cap, &used, "[JIT] jumping into the generated page\n");

	int (*fn)(void) = (int (*)(void))(void *)p;
	int value = fn();

	append(out, cap, &used, "[JIT] returned %d expected=42 %s\n",
	       value, value == 42 ? "OK" : "MISMATCH");

	munmap(p, page);
}
