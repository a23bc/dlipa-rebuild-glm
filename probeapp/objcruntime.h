#ifndef OBJC_RUNTIME_H
#define OBJC_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

/* Minimal Objective-C runtime for running CommerceKit inside the TCI
 * emulator.
 *
 * CommerceKit is an Objective-C framework, so its code sends messages. Those
 * sends arrive at shim slots as calls to objc_msgSend, and this file answers
 * them: the receiver's isa identifies a class, the selector identifies a
 * method, and the method's implementation is a guest address to jump to.
 *
 * The runtime never touches guest memory itself. It owns no engine, so the
 * caller reads the receiver's isa and passes it in. That keeps the dependency
 * one-way: emulator -> runtime, never runtime -> emulator. */

/* Called once after the image is mapped. Interns every selector name and
 * assigns each class a guest address. */
void objc_runtime_init(void);

/* Guest address of a class object, or 0 when the class is unknown. */
uint64_t objc_class_address(const char *name);

/* Guest address of a selector handle, or 0 when the selector is unknown. */
uint64_t objc_selector(const char *name);

/* Resolves a message send. `isa` is the class object address read out of the
 * receiver. Returns the implementation's link-time address, or 0 with
 * *stop_reason set when the message cannot be answered. */
uint64_t objc_lookup(uint64_t isa, uint64_t selector, const char **stop_reason);

/* Number of classes and interned selectors, for the report. */
int objc_class_count(void);
int objc_selector_count(void);

#endif
