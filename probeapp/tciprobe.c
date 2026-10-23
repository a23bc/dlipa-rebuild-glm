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
#include <mach/mach.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

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

/* Stage 2a: is the interpreter fast enough to be worth building on?
 *
 * TCI interprets every guest instruction, so the question is not whether it
 * works - it does - but whether it works at a rate that makes a 15 MB library
 * practical. The loop below is timed from the host side and reports
 * instructions per second.
 *
 * The run is bounded by Unicorn's own timeout argument rather than by a
 * fixed iteration count: if the interpreter turns out to be pathologically
 * slow, a fixed count would hang the app, and the number wanted is a rate,
 * which a partial run gives just as well. Afterwards the loop counter says
 * how far it got.
 *
 * The second half maps the amount of guest memory CoreFP would need and
 * writes through it. This device has 2 GB and the emulator holds the guest
 * image in host memory, so that is worth knowing before committing. */
void benchprobe_report(char *out, size_t cap)
{
	if (cap == 0) {
		return;
	}
	out[0] = 0;
	size_t used = 0;

	/* mov rcx, 0x7fffffff ; dec rcx ; jne -5 */
	static const uint8_t loop_code[] = {
		0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0x7f,
		0x48, 0xff, 0xc9,
		0x75, 0xfb,
	};

	uc_engine *uc = NULL;
	uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err != UC_ERR_OK) {
		append(out, cap, &used, "[BENCH] uc_open failed: %u\n", err);
		return;
	}

	if (uc_mem_map(uc, 0x100000, 0x4000, UC_PROT_ALL) != UC_ERR_OK ||
	    uc_mem_write(uc, 0x100000, loop_code, sizeof(loop_code)) != UC_ERR_OK) {
		append(out, cap, &used, "[BENCH] setup failed\n");
		uc_close(uc);
		return;
	}

	struct timespec started, finished;
	clock_gettime(CLOCK_MONOTONIC, &started);

	/* At most 1.5 s. The return code is not interesting; the counter is: a
	 * timeout still leaves a valid rate, computed from how many iterations
	 * completed. */
	err = uc_emu_start(uc, 0x100000, 0x100000 + sizeof(loop_code), 1500000, 0);

	clock_gettime(CLOCK_MONOTONIC, &finished);

	double seconds = (double)(finished.tv_sec - started.tv_sec) +
	                 (double)(finished.tv_nsec - started.tv_nsec) / 1e9;

	uint64_t remaining = 0;
	uc_reg_read(uc, UC_X86_REG_RCX, &remaining);
	uc_close(uc);

	uint64_t iterations = 0x7fffffffULL - remaining;
	double instructions = 1.0 + 2.0 * (double)iterations;
	double rate = seconds > 0.0 ? instructions / seconds : 0.0;

	append(out, cap, &used, "[BENCH] loop err=%u elapsed=%.3fs iterations=%llu\n",
	       err, seconds, (unsigned long long)iterations);
	append(out, cap, &used, "[BENCH] throughput=%.0f instr/s (%.2f M/s)\n",
	       rate, rate / 1e6);

	if (rate > 0.0) {
		append(out, cap, &used, "[BENCH] 100M instructions would take %.1f s\n",
		       1e8 / rate);
	}

	/* Memory: map what CoreFP's segments would need and write through it. */
	uc_engine *big = NULL;
	err = uc_open(UC_ARCH_X86, UC_MODE_64, &big);
	if (err == UC_ERR_OK) {
		uint64_t base = 0x100000000ULL;
		size_t size = (size_t)64 << 20;
		clock_gettime(CLOCK_MONOTONIC, &started);
		err = uc_mem_map(big, base, size, UC_PROT_ALL);
		clock_gettime(CLOCK_MONOTONIC, &finished);
		double map_seconds = (double)(finished.tv_sec - started.tv_sec) +
		                     (double)(finished.tv_nsec - started.tv_nsec) / 1e9;

		if (err == UC_ERR_OK) {
			static uint8_t page[0x4000];
			memset(page, 0xa5, sizeof(page));
			clock_gettime(CLOCK_MONOTONIC, &started);
			for (size_t at = 0; at < ((size_t)16 << 20); at += sizeof(page)) {
				if (uc_mem_write(big, base + at, page, sizeof(page)) != UC_ERR_OK) {
					break;
				}
			}
			clock_gettime(CLOCK_MONOTONIC, &finished);
			double write_seconds = (double)(finished.tv_sec - started.tv_sec) +
			                        (double)(finished.tv_nsec - started.tv_nsec) / 1e9;
			append(out, cap, &used,
			       "[BENCH] mapped 64 MB in %.3fs, wrote 16 MB in %.3fs\n",
			       map_seconds, write_seconds);
		} else {
			append(out, cap, &used, "[BENCH] 64 MB map FAILED err=%u\n", err);
		}
		uc_close(big);
	}

	struct mach_task_basic_info info;
	mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
	if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
	              (task_info_t)&info, &count) == KERN_SUCCESS) {
		append(out, cap, &used, "[BENCH] app resident=%.1f MB\n",
		       (double)info.resident_size / (1024.0 * 1024.0));
	}
}
