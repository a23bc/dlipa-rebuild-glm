#ifndef X64PROBE_H
#define X64PROBE_H

#include <stddef.h>

/* Loads the guest image produced by cmd/x86image and runs CoreFP's first
 * exported entry under the interpreter, stopping at the first import call so
 * the report names the shim that has to be written next. */
/* mode 0 surveys every export with zeroed arguments.
 * mode 1 calls _cp2g1b9ro the way the SAP driver does: rdi points at an
 * eight-byte context slot, rsi at the hardware block, and the return value is
 * the status. */
void x64probe_report(const char *image_path, int mode, char *out, size_t cap);

#endif
