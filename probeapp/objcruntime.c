/* Minimal Objective-C runtime. See objcruntime.h for the contract.
 *
 * Two lookups happen here and both are linear scans over static tables. That
 * is fine: the tables are small, the number of sends per run is in the
 * hundreds, and a hash table would add a failure mode for no measurable
 * gain. */

#include "objcruntime.h"
#include "objctable.h"

#include <string.h>

#define OBJC_CLASS_BASE    0x300000000ULL
#define OBJC_CLASS_STRIDE  0x40
#define OBJC_SELECTOR_BASE 0x310000000ULL
#define OBJC_SELECTOR_STRIDE 0x40
#define OBJC_MAX_SELECTORS 4096

static uint64_t g_class_addr[OBJC_CLASS_COUNT];
static int g_ready;

typedef struct {
	const char *name;
	uint64_t handle;
} interned_selector;

static interned_selector g_selectors[OBJC_MAX_SELECTORS];
static int g_selector_count;

void objc_runtime_init(void)
{
	for (int i = 0; i < OBJC_CLASS_COUNT; i++) {
		g_class_addr[i] = OBJC_CLASS_BASE + (uint64_t)i * OBJC_CLASS_STRIDE;
	}

	g_selector_count = 0;
	for (int i = 0; i < OBJC_METHOD_COUNT; i++) {
		const char *name = objc_methods[i].sel;
		if (name == NULL || name[0] == 0) {
			continue;
		}
		int seen = 0;
		for (int k = 0; k < g_selector_count; k++) {
			if (strcmp(g_selectors[k].name, name) == 0) {
				seen = 1;
				break;
			}
		}
		if (!seen && g_selector_count < OBJC_MAX_SELECTORS) {
			g_selectors[g_selector_count].name = name;
			g_selectors[g_selector_count].handle =
			    OBJC_SELECTOR_BASE + (uint64_t)g_selector_count * OBJC_SELECTOR_STRIDE;
			g_selector_count++;
		}
	}

	g_ready = 1;
}

int objc_class_count(void) { return OBJC_CLASS_COUNT; }
int objc_selector_count(void) { return g_selector_count; }

uint64_t objc_class_address(const char *name)
{
	if (!g_ready || name == NULL) {
		return 0;
	}
	for (int i = 0; i < OBJC_CLASS_COUNT; i++) {
		if (strcmp(objc_classes[i].name, name) == 0) {
			return g_class_addr[i];
		}
	}
	return 0;
}

uint64_t objc_selector(const char *name)
{
	if (!g_ready || name == NULL) {
		return 0;
	}
	for (int k = 0; k < g_selector_count; k++) {
		if (strcmp(g_selectors[k].name, name) == 0) {
			return g_selectors[k].handle;
		}
	}
	return 0;
}

static const char *selector_name(uint64_t selector)
{
	for (int k = 0; k < g_selector_count; k++) {
		if (g_selectors[k].handle == selector) {
			return g_selectors[k].name;
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

uint64_t objc_lookup(uint64_t isa, uint64_t selector, const char **stop_reason)
{
	*stop_reason = NULL;

	if (!g_ready) {
		*stop_reason = "objc runtime not initialised";
		return 0;
	}

	const char *name = selector_name(selector);
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
