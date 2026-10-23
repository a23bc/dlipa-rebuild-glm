#ifndef X64PROBE_H
#define X64PROBE_H

#include <stddef.h>
#include <stdint.h>

/* Loads the guest image produced by cmd/x86image and runs CoreFP's first
 * exported entry under the interpreter, stopping at the first import call so
 * the report names the shim that has to be written next. */
/* mode 0 surveys every export with zeroed arguments.
 * mode 1 calls _cp2g1b9ro the way the SAP driver does: rdi points at an
 * eight-byte context slot, rsi at the hardware block, and the return value is
 * the status. */
void x64probe_report(const char *image_path, int mode, char *out, size_t cap);

/* The HTTP round trip between the two SAP exchange calls belongs to the app:
 * the guest is synchronous and has no network stack. The app installs a
 * callback, and the driver calls it with the request the library produced and
 * feeds the reply into the second exchange. Returning 0 means the reply is
 * valid; any other value stops the chain and is reported. */
typedef int (*sap_post_fn)(const uint8_t *request, size_t request_len,
                           uint8_t *reply, size_t reply_cap, size_t *reply_len);
void x64probe_set_post(sap_post_fn fn);

#endif
