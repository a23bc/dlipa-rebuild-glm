#ifndef TCIPROBE_H
#define TCIPROBE_H

#include <stddef.h>

/* Runs the TCI (interpreter) emulator against a small x86-64 guest and
 * writes a human-readable report into out. Never returns a partial line. */
void tciprobe_report(char *out, size_t cap);

#endif
