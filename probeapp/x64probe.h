#ifndef X64PROBE_H
#define X64PROBE_H

#include <stddef.h>

/* Loads the guest image produced by cmd/x86image and runs CoreFP's first
 * exported entry under the interpreter, stopping at the first import call so
 * the report names the shim that has to be written next. */
void x64probe_report(const char *image_path, char *out, size_t cap);

#endif
