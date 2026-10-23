#ifndef SAP_OBJC_H
#define SAP_OBJC_H

#include <stddef.h>
#include <stdint.h>

/* Minimal Objective-C runtime for running CommerceKit inside the TCI
 * emulator. Ported from probeapp/objcruntime.c. */

typedef struct sap_objc sap_objc;

/* Called once after the image is mapped. Interns every selector name and
 * assigns each class a guest address. */
void sap_objc_init(sap_objc *runtime);

/* Guest address of a class object, or 0 when the class is unknown. */
uint64_t sap_objc_class_address(const sap_objc *runtime, const char *name);

/* Guest address of a selector handle, or 0 when the selector is unknown. */
uint64_t sap_objc_selector(const sap_objc *runtime, const char *name);

/* Resolves a message send. isa is the class object address read out of the
 * receiver. Returns the implementation's link-time address, or 0 with
 * *stop_reason set when the message cannot be answered. */
uint64_t sap_objc_lookup(sap_objc *runtime, uint64_t isa, uint64_t selector,
                         const char **stop_reason);

int sap_objc_class_count(void);
int sap_objc_selector_count(const sap_objc *runtime);

/* The process-wide runtime. probeapp kept this as file-scope statics. */
sap_objc *sap_objc_shared(void);

#endif
