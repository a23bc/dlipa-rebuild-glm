//go:build ios

package unicorn

/*

// Referencing Unicorn symbols from compiled code forces the linker to pull
// them out of libunicorn.a. Relying on -force_load alone is fragile: if that
// flag is dropped the archive is simply not linked, and purego.Dlsym then
// fails at runtime with an error that only shows up on a device.
//
// Only built for ios. The macOS host test build has no libunicorn.a to resolve
// these references against, so including darwin here would break go test.
//
// No #cgo LDFLAGS here on purpose. Go rejects -Wl,-export_dynamic inside the
// directive with "invalid flag in #cgo LDFLAGS", so the export flag is passed
// through the CGO_LDFLAGS environment variable instead, which the workflow sets
// for the gomobile bind step. This file only needs the undefined references.
extern unsigned int uc_version(unsigned int *major, unsigned int *minor);
extern int uc_open(int arch, int mode, void **uc);
extern int uc_close(void *uc);
extern int uc_mem_map(void *uc, unsigned long long address, unsigned long long size, unsigned int perms);
extern int uc_mem_write(void *uc, unsigned long long address, const void *bytes, unsigned long long size);
extern int uc_mem_read(void *uc, unsigned long long address, void *bytes, unsigned long long size);
extern int uc_mem_unmap(void *uc, unsigned long long address, unsigned long long size);
extern int uc_emu_start(void *uc, unsigned long long begin, unsigned long long until, unsigned long long timeout, unsigned long long count);
extern int uc_emu_stop(void *uc);
extern int uc_reg_read(void *uc, int regid, void *value);
extern int uc_reg_write(void *uc, int regid, const void *value);
extern int uc_hook_add(void *uc, void **hook, int type, void *callback, void *user_data, unsigned long long begin, unsigned long long end);
extern int uc_hook_del(void *uc, void *hook);
extern const char *uc_strerror(int code);
extern int uc_ctl(void *uc, unsigned int control, unsigned int arg);
extern int uc_query(void *uc, int query_type, unsigned long long *result);

// forceUnicornLink records the addresses of every uc_* symbol into a volatile
// array. It must NOT call any uc_* function: an earlier version of this file
// called uc_open + uc_reg_read(uc, 199, NULL) to "use" the symbols, but
// uc_reg_read dereferences the value pointer without a NULL check, so the
// init() call from the Go side crashed the app at startup. Taking the address
// of each symbol creates the reference the linker needs without executing any
// Unicorn code, which is all that was ever required.
static void forceUnicornLink(void) {
    static volatile void *const symbols[] = {
        (void *)uc_version,
        (void *)uc_open,
        (void *)uc_close,
        (void *)uc_mem_map,
        (void *)uc_mem_write,
        (void *)uc_mem_read,
        (void *)uc_mem_unmap,
        (void *)uc_emu_start,
        (void *)uc_emu_stop,
        (void *)uc_reg_read,
        (void *)uc_reg_write,
        (void *)uc_hook_add,
        (void *)uc_hook_del,
        (void *)uc_strerror,
        (void *)uc_ctl,
        (void *)uc_query,
    };
    // The array is volatile so the compiler cannot delete it as dead code.
    // Reading it back through the volatile pointer is enough to keep the
    // references live without calling any of the functions.
    (void)symbols[0];
}
*/
import "C"

// ForceLink calls the C shim above. It is exported so the Go compiler must
// keep the translation unit that carries the undefined Unicorn references.
func ForceLink() {
        C.forceUnicornLink()
}
