// B0: does this TCI build actually execute aarch64 instructions?
//
// Linking proves nothing -- a JIT-only or wrong-arch archive links just as well
// and then fails at uc_open or produces garbage. This runs one instruction and
// checks the register it writes.
//
//     mov x0, #42      ; 0xD2800540
//
// Only one instruction is executed on purpose: adding "ret" would need a valid
// link register and turn a register check into a control-flow test.
#include <stdio.h>
#include <stdint.h>
#include <unicorn/unicorn.h>

#define CODE_ADDR 0x1000u

int main(void) {
    static const uint32_t code[] = { 0xD2800540u };  // mov x0, #42

    uc_engine *uc = NULL;
    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        printf("FAIL uc_open(ARM64): %s\n", uc_strerror(err));
        return 1;
    }

    if ((err = uc_mem_map(uc, CODE_ADDR, 0x1000, UC_PROT_ALL)) != UC_ERR_OK) {
        printf("FAIL uc_mem_map: %s\n", uc_strerror(err));
        return 1;
    }
    if ((err = uc_mem_write(uc, CODE_ADDR, code, sizeof(code))) != UC_ERR_OK) {
        printf("FAIL uc_mem_write: %s\n", uc_strerror(err));
        return 1;
    }

    err = uc_emu_start(uc, CODE_ADDR, CODE_ADDR + 4, 0, 1);
    if (err != UC_ERR_OK) {
        printf("FAIL uc_emu_start: %s\n", uc_strerror(err));
        return 1;
    }

    uint64_t x0 = 0;
    if ((err = uc_reg_read(uc, UC_ARM64_REG_X0, &x0)) != UC_ERR_OK) {
        printf("FAIL uc_reg_read(X0): %s\n", uc_strerror(err));
        return 1;
    }

    uc_close(uc);

    if (x0 != 42) {
        printf("FAIL x0=%llu, expected 42 -- the instruction did not execute\n",
               (unsigned long long)x0);
        return 1;
    }
    printf("PASS aarch64 executed under TCI: x0=%llu\n", (unsigned long long)x0);
    return 0;
}
