// Exercises the code_gen_alloc path on the archive that ships in the app.
//
// The device dies inside QEMU's code_gen_alloc with
//     Could not allocate dynamic translator buffer
// and QEMU calls exit(1) there, so there is no crash report to read. Running the
// same sequence in CI turns that into an exit code and a line of output.
//
// The buffer size is applied before uc_open's lazy UC_INIT, and read back after,
// so the log shows which value code_gen_alloc actually used.
#include <stdio.h>
#include <stdint.h>
#include <unicorn/unicorn.h>

int main(void) {
    uc_engine *uc = NULL;

    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        printf("FAIL uc_open(ARM64): %s\n", uc_strerror(err));
        return 1;
    }
    printf("uc_open ok\n");

    uint32_t size = 0;
    if (uc_ctl_get_tcg_buffer_size(uc, &size) == UC_ERR_OK) {
        printf("tcg buffer before set: %u bytes\n", size);
    }

    err = uc_ctl_set_tcg_buffer_size(uc, 8u << 20);
    if (err != UC_ERR_OK) {
        printf("FAIL set buffer: %s\n", uc_strerror(err));
        return 1;
    }
    if (uc_ctl_get_tcg_buffer_size(uc, &size) == UC_ERR_OK) {
        printf("tcg buffer after set:  %u bytes\n", size);
    }

    // The first call that triggers UC_INIT -> tcg_exec_init -> code_gen_alloc.
    static const uint32_t code[] = { 0xD2800540u };  // mov x0, #42
    if ((err = uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL)) != UC_ERR_OK) {
        printf("FAIL uc_mem_map: %s\n", uc_strerror(err));
        return 1;
    }
    printf("uc_mem_map ok -- code_gen_alloc survived\n");

    if (uc_ctl_get_tcg_buffer_size(uc, &size) == UC_ERR_OK) {
        printf("tcg buffer after init: %u bytes\n", size);
    }

    uc_mem_write(uc, 0x1000, code, sizeof(code));
    err = uc_emu_start(uc, 0x1000, 0x1004, 0, 1);
    if (err != UC_ERR_OK) {
        printf("FAIL uc_emu_start: %s\n", uc_strerror(err));
        return 1;
    }

    uint64_t x0 = 0;
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    uc_close(uc);

    if (x0 != 42) {
        printf("FAIL x0=%llu\n", (unsigned long long)x0);
        return 1;
    }
    printf("PASS aarch64 executed, x0=%llu\n", (unsigned long long)x0);
    return 0;
}
