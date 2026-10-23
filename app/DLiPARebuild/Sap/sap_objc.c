/* Minimal Objective-C runtime for the SAP guest.
 *
 * Ported from probeapp/objcruntime.c, which is the implementation that made
 * CommerceKit run under the interpreter. The lookup rules are unchanged: the
 * receiver's isa selects a class, the selector selects a method, and the
 * method's implementation is a guest address to jump to.
 *
 * The runtime never touches guest memory itself. It owns no engine, so the
 * caller reads the receiver's isa and passes it in. That keeps the dependency
 * one-way: emulator -> runtime, never runtime -> emulator.
 */

#include "sap_objc.h"
#include "objctable.h"

#include <string.h>

#define OBJC_CLASS_BASE     0x300000000ULL
#define OBJC_CLASS_STRIDE   0x40
#define OBJC_SELECTOR_BASE  0x310000000ULL
#define OBJC_SELECTOR_STRIDE 0x40
#define OBJC_MAX_SELECTORS  4096

typedef struct {
    const char *name;
    uint64_t handle;
} interned_selector;

struct sap_objc {
    uint64_t class_addr[OBJC_CLASS_COUNT];
    interned_selector selectors[OBJC_MAX_SELECTORS];
    int selector_count;
    int ready;
};

/* One runtime per guest, so two handles never share interned selectors. The
 * table itself is static and read-only, which is why it can be shared. */
static struct sap_objc g_runtime;
static int g_initialised;

void sap_objc_init(sap_objc *runtime)
{
    if (runtime == NULL) {
        return;
    }
    for (int i = 0; i < OBJC_CLASS_COUNT; i++) {
        runtime->class_addr[i] =
            OBJC_CLASS_BASE + (uint64_t)i * OBJC_CLASS_STRIDE;
    }

    runtime->selector_count = 0;
    for (int i = 0; i < OBJC_METHOD_COUNT; i++) {
        const char *name = objc_methods[i].sel;
        if (name == NULL || name[0] == 0) {
            continue;
        }
        int seen = 0;
        for (int k = 0; k < runtime->selector_count; k++) {
            if (strcmp(runtime->selectors[k].name, name) == 0) {
                seen = 1;
                break;
            }
        }
        if (!seen && runtime->selector_count < OBJC_MAX_SELECTORS) {
            runtime->selectors[runtime->selector_count].name = name;
            runtime->selectors[runtime->selector_count].handle =
                OBJC_SELECTOR_BASE +
                (uint64_t)runtime->selector_count * OBJC_SELECTOR_STRIDE;
            runtime->selector_count++;
        }
    }

    runtime->ready = 1;
}

int sap_objc_class_count(void) { return OBJC_CLASS_COUNT; }
int sap_objc_selector_count(const sap_objc *runtime)
{
    return runtime != NULL ? runtime->selector_count : 0;
}

uint64_t sap_objc_class_address(const sap_objc *runtime, const char *name)
{
    if (runtime == NULL || !runtime->ready || name == NULL) {
        return 0;
    }
    for (int i = 0; i < OBJC_CLASS_COUNT; i++) {
        if (strcmp(objc_classes[i].name, name) == 0) {
            return runtime->class_addr[i];
        }
    }
    return 0;
}

uint64_t sap_objc_selector(const sap_objc *runtime, const char *name)
{
    if (runtime == NULL || !runtime->ready || name == NULL) {
        return 0;
    }
    for (int k = 0; k < runtime->selector_count; k++) {
        if (strcmp(runtime->selectors[k].name, name) == 0) {
            return runtime->selectors[k].handle;
        }
    }
    return 0;
}

static const char *selector_name(const sap_objc *runtime, uint64_t selector)
{
    for (int k = 0; k < runtime->selector_count; k++) {
        if (runtime->selectors[k].handle == selector) {
            return runtime->selectors[k].name;
        }
    }
    return NULL;
}

static int class_index_for_isa(uint64_t isa)
{
    if (isa < OBJC_CLASS_BASE) {
        return -1;
    }
    uint64_t offset = isa - OBJC_CLASS_BASE;
    if (offset % OBJC_CLASS_STRIDE != 0) {
        return -1;
    }
    uint64_t index = offset / OBJC_CLASS_STRIDE;
    if (index >= (uint64_t)OBJC_CLASS_COUNT) {
        return -1;
    }
    return (int)index;
}

uint64_t sap_objc_lookup(sap_objc *runtime, uint64_t isa, uint64_t selector,
                         const char **stop_reason)
{
    *stop_reason = NULL;

    if (runtime == NULL || !runtime->ready) {
        *stop_reason = "objc runtime not initialised";
        return 0;
    }

    const char *name = selector_name(runtime, selector);
    if (name == NULL) {
        *stop_reason = "selector handle is not one this runtime issued";
        return 0;
    }

    int index = class_index_for_isa(isa);
    if (index < 0) {
        *stop_reason = "receiver isa is not a class object this runtime issued";
        return 0;
    }

    const objc_class_t *cls = &objc_classes[index];
    for (uint32_t i = 0; i < cls->count; i++) {
        const objc_method_t *m = &objc_methods[cls->first + i];
        if (m->sel != NULL && strcmp(m->sel, name) == 0) {
            return m->imp;
        }
    }

    *stop_reason = name;
    return 0;
}

/* The single runtime used by the guest. probeapp used file-scope statics; the
 * library keeps one instance so the call sites stay as short as they were. */
sap_objc *sap_objc_shared(void)
{
    if (!g_initialised) {
        sap_objc_init(&g_runtime);
        g_initialised = 1;
    }
    return &g_runtime;
}
