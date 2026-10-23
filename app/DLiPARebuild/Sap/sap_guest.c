/* SAP signer backed by the x86-64 CommerceKit guest.
 *
 * The guest image is the X64I container produced by sapbridge/cmd/x86image:
 * a flat file holding the segments, the import names, the rebase and bind
 * tables, and the exported entry points. Nothing in this file knows about
 * the probe app; the container format and the addressing rules are the only
 * things carried over from it.
 *
 * Layout of the container, little endian throughout:
 *
 *   0   "X64I"
 *   4   u32 version, must be 1
 *   8   u32 segment count
 *   12  u32 import count
 *   16  u32 rebase count
 *   20  u32 bind count
 *   24  u32 entry count
 *   28  segment table, 40 bytes per entry:
 *         char name[16]
 *         u64  vmaddr
 *         u64  vmsize
 *         u32  prot
 *         u32  content_len
 *       followed by the segment contents, concatenated in order.
 *       The import, rebase, bind and entry tables follow those contents.
 */

#include "sap_guest.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#define SAP_IMAGE_VERSION 1
#define SAP_MAX_SEGMENTS 8
#define SAP_MAX_IMPORTS 512

/* Guest address space. These are fixed by the loader that produced the image
 * and are not negotiable at run time: the rebase and bind entries in the
 * container are absolute addresses in this same space. */
static const uint64_t k_base      = 0x100000000ULL;  /* image segments */
static const uint64_t k_stub_base = 0x700000000ULL;  /* one 16-byte slot per import */
static const uint64_t k_data_base = 0x710000000ULL;
static const uint64_t k_stack_base = 0x800000000ULL;
static const uint64_t k_heap_base = 0x600000000ULL;
static const uint64_t k_heap_size = 64ULL << 20;
static const uint64_t k_trampoline = 0x500000000ULL;
static const uint64_t k_stub_slot = 16;

struct sap_segment {
    char name[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint32_t prot;
    uint32_t content_len;
    const uint8_t *content;
};

struct sap_guest {
    uc_engine *uc;
    uint8_t *blob;          /* the container, kept alive while the guest runs */
    size_t blob_len;

    struct sap_segment segs[SAP_MAX_SEGMENTS];
    uint32_t seg_count;

    uint32_t import_count;
    uint32_t rebase_count;
    uint32_t bind_count;
    uint32_t entry_count;

    /* Cursor into the container where the import table starts. The tables
     * after it are parsed in sap_tables_load. */
    const uint8_t *tables;
    char import_names[SAP_MAX_IMPORTS][128];
    uint32_t data_cursor;

    uint64_t heap_cursor;
    sap_post_fn post;
    void *userdata;

    sap_guest_stats stats;
};

static uint32_t rd32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static uint64_t rd64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static void set_error(char *error, size_t cap, const char *fmt, ...)
{
    if (error == NULL || cap == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(error, cap, fmt, ap);
    va_end(ap);
}

static int prot_to_unicorn(uint32_t prot)
{
    int out = 0;
    if (prot & 1) out |= UC_PROT_READ;
    if (prot & 2) out |= UC_PROT_WRITE;
    if (prot & 4) out |= UC_PROT_EXEC;
    return out == 0 ? UC_PROT_ALL : out;
}

static int read_file(const char *path, uint8_t **out_blob, size_t *out_len,
                     char *error, size_t cap)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        set_error(error, cap, "cannot open image: %s", path);
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        set_error(error, cap, "cannot seek image");
        return -1;
    }
    long size = ftell(file);
    if (size <= 0) {
        fclose(file);
        set_error(error, cap, "image is empty");
        return -1;
    }
    rewind(file);

    uint8_t *blob = (uint8_t *)malloc((size_t)size);
    if (blob == NULL) {
        fclose(file);
        set_error(error, cap, "out of memory reading image");
        return -1;
    }
    size_t got = fread(blob, 1, (size_t)size, file);
    fclose(file);
    if (got != (size_t)size) {
        free(blob);
        set_error(error, cap, "short read on image");
        return -1;
    }
    *out_blob = blob;
    *out_len = (size_t)size;
    return 0;
}

/* Parses the header and the segment table, then maps every segment into the
 * guest at its recorded address. The contents are copied, not aliased, since
 * the guest writes to the writable ones. */
static int load_segments(struct sap_guest *g, char *error, size_t cap)
{
    const uint8_t *blob = g->blob;
    if (g->blob_len < 28 || memcmp(blob, "X64I", 4) != 0) {
        set_error(error, cap, "not an X64I container");
        return -1;
    }
    if (rd32(blob + 4) != SAP_IMAGE_VERSION) {
        set_error(error, cap, "container version %u, expected %u",
                  rd32(blob + 4), SAP_IMAGE_VERSION);
        return -1;
    }

    g->seg_count = rd32(blob + 8);
    g->import_count = rd32(blob + 12);
    g->rebase_count = rd32(blob + 16);
    g->bind_count = rd32(blob + 20);
    g->entry_count = rd32(blob + 24);

    if (g->seg_count == 0 || g->seg_count > SAP_MAX_SEGMENTS) {
        set_error(error, cap, "segment count %u out of range", g->seg_count);
        return -1;
    }
    if (g->blob_len < 28 + (size_t)g->seg_count * 40) {
        set_error(error, cap, "segment table is truncated");
        return -1;
    }

    const uint8_t *cursor = blob + 28;
    for (uint32_t i = 0; i < g->seg_count; i++) {
        struct sap_segment *s = &g->segs[i];
        memcpy(s->name, cursor, 16);
        s->name[15] = 0;
        s->vmaddr = rd64(cursor + 16);
        s->vmsize = rd64(cursor + 24);
        s->prot = rd32(cursor + 32);
        s->content_len = rd32(cursor + 36);
        cursor += 40;
    }
    for (uint32_t i = 0; i < g->seg_count; i++) {
        struct sap_segment *s = &g->segs[i];
        if ((size_t)(cursor - blob) + s->content_len > g->blob_len) {
            set_error(error, cap, "segment %s content runs past the file", s->name);
            return -1;
        }
        s->content = cursor;
        cursor += s->content_len;
    }

    /* Everything after the contents is the import, rebase, bind and entry
     * tables. Their layout is parsed by sap_tables_load, which is not
     * written yet; the cursor is recorded so the next step starts here. */
    g->tables = cursor;

    for (uint32_t i = 0; i < g->seg_count; i++) {
        struct sap_segment *s = &g->segs[i];
        uint64_t size = s->vmsize > s->content_len ? s->vmsize : s->content_len;
        if (size == 0) {
            continue;
        }
        uint64_t aligned = (size + 0xFFF) & ~0xFFFULL;
        /* The container records vmaddr relative to the image base, but the
         * rebase and bind tables hold absolute guest addresses. Everything
         * therefore lands at k_base + vmaddr. */
        uc_err err = uc_mem_map(g->uc, k_base + s->vmaddr, aligned,
                                prot_to_unicorn(s->prot));
        if (err != UC_ERR_OK) {
            set_error(error, cap, "cannot map segment %s at 0x%llx: %s",
                      s->name, (unsigned long long)s->vmaddr, uc_strerror(err));
            return -1;
        }
        if (s->content_len > 0) {
            err = uc_mem_write(g->uc, k_base + s->vmaddr, s->content,
                               s->content_len);
            if (err != UC_ERR_OK) {
                set_error(error, cap, "cannot write segment %s: %s",
                          s->name, uc_strerror(err));
                return -1;
            }
        }
    }
    return 0;
}

/* The stub area and the stack are not in the container: they are addressing
 * space the loader reserves. One 16-byte slot per import, so a stub is always
 * k_stub_base + slot * 16, and a stack page the guest can grow down into. */
static int load_scratch(struct sap_guest *g, char *error, size_t cap)
{
    uint64_t stub_size = ((uint64_t)g->import_count * k_stub_slot + 0xFFF) & ~0xFFFULL;
    if (stub_size > 0) {
        uc_err err = uc_mem_map(g->uc, k_stub_base, stub_size, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            set_error(error, cap, "cannot map stubs: %s", uc_strerror(err));
            return -1;
        }
        /* Every slot starts as a bare ret. An import that never gets bound
         * then returns to its caller instead of running into int3 padding,
         * which turns a missing binding into a wrong value rather than a
         * crash far away from the cause. */
        uint8_t slot[16];
        memset(slot, 0xCC, sizeof(slot));
        slot[0] = 0xC3;
        for (uint32_t i = 0; i < g->import_count; i++) {
            err = uc_mem_write(g->uc, k_stub_base + (uint64_t)i * k_stub_slot,
                               slot, sizeof(slot));
            if (err != UC_ERR_OK) {
                set_error(error, cap, "cannot fill stub %u: %s", i, uc_strerror(err));
                return -1;
            }
        }
    }

    const uint64_t stack_size = 8ULL << 20;
    uc_err err = uc_mem_map(g->uc, k_stack_base, stack_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        set_error(error, cap, "cannot map stack: %s", uc_strerror(err));
        return -1;
    }

    err = uc_mem_map(g->uc, k_heap_base, k_heap_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        set_error(error, cap, "cannot map heap: %s", uc_strerror(err));
        return -1;
    }
    g->heap_cursor = k_heap_base;

    if (k_data_base != 0) {
        err = uc_mem_map(g->uc, k_data_base, 0x10000, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            set_error(error, cap, "cannot map data: %s", uc_strerror(err));
            return -1;
        }
    }
    return 0;
}

static int is_data_import(const char *name)
{
    if (strncmp(name, "_k", 2) == 0) {
        return 1;
    }
    return strcmp(name, "___stack_chk_guard") == 0;
}

/* Walks the three tables that follow the segment contents: the import names,
 * the rebase list and the bind list. Rebase entries hold addresses relative to
 * the image base and every value they point at has to move by k_base, because
 * the segments were mapped there. Bind records carry an addend as well as a
 * slot: the value written is the target plus that addend. */
static int load_tables(struct sap_guest *g, char *error, size_t cap)
{
    const uint8_t *cursor = g->tables;
    size_t remaining = g->blob_len - (size_t)(cursor - g->blob);
    size_t import_bytes = (size_t)g->import_count * 128;
    size_t rebase_bytes = (size_t)g->rebase_count * 8;
    size_t bind_bytes = (size_t)g->bind_count * 16;
    if (g->import_count > SAP_MAX_IMPORTS) {
        set_error(error, cap, "import count %u out of range", g->import_count);
        return -1;
    }
    if (import_bytes + rebase_bytes + bind_bytes > remaining) {
        set_error(error, cap, "import/rebase/bind tables run past the file");
        return -1;
    }

    for (uint32_t i = 0; i < g->import_count; i++) {
        memcpy(g->import_names[i], cursor, 128);
        g->import_names[i][127] = 0;
        cursor += 128;
    }

    const uint8_t *rebase = cursor;
    cursor += rebase_bytes;
    const uint8_t *bind = cursor;

    for (uint32_t i = 0; i < g->rebase_count; i++) {
        uint64_t addr = rd64(rebase + (size_t)i * 8);
        uint64_t value = 0;
        if (uc_mem_read(g->uc, k_base + addr, &value, 8) != UC_ERR_OK) {
            continue;
        }
        value += k_base;
        uc_mem_write(g->uc, k_base + addr, &value, 8);
    }

    /* Data imports get their own 64-byte cell each, handed out in bind order.
     * They are variables the guest reads through a pointer, not functions, so
     * they must not land in the stub area. */
    uint32_t data_cursor = 0;
    for (uint32_t i = 0; i < g->bind_count; i++) {
        const uint8_t *rec = bind + (size_t)i * 16;
        uint64_t addr = rd64(rec);
        uint32_t slot = rd32(rec + 8);
        int32_t addend = (int32_t)rd32(rec + 12);
        if (slot >= g->import_count) {
            continue;
        }
        uint64_t target;
        if (is_data_import(g->import_names[slot])) {
            target = k_data_base + (uint64_t)data_cursor * 64;
            data_cursor++;
        } else {
            target = k_stub_base + (uint64_t)slot * k_stub_slot;
        }
        uint64_t value = target + (uint64_t)(int64_t)addend;
        uc_err err = uc_mem_write(g->uc, k_base + addr, &value, 8);
        if (err != UC_ERR_OK) {
            set_error(error, cap, "cannot bind slot %u at 0x%llx: %s",
                      slot, (unsigned long long)addr, uc_strerror(err));
            return -1;
        }
    }

    g->data_cursor = data_cursor;
    return 0;
}

/* Guest calls return here: one page holding a bare ret. */
static int load_trampoline(struct sap_guest *g, char *error, size_t cap)
{
    uc_err err = uc_mem_map(g->uc, k_trampoline, 0x1000, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        set_error(error, cap, "cannot map trampoline: %s", uc_strerror(err));
        return -1;
    }
    const uint8_t ret = 0xC3;
    err = uc_mem_write(g->uc, k_trampoline, &ret, 1);
    if (err != UC_ERR_OK) {
        set_error(error, cap, "cannot write trampoline: %s", uc_strerror(err));
        return -1;
    }
    return 0;
}
sap_guest *sap_guest_new(const sap_guest_config *cfg, char *error, size_t cap)
{
    if (cfg == NULL || cfg->image_path == NULL) {
        set_error(error, cap, "no image path");
        return NULL;
    }
    if (cfg->hardware_id == NULL || cfg->hardware_id_len == 0 ||
        cfg->hardware_id_len > 20) {
        set_error(error, cap, "hardware id must be 1..20 bytes");
        return NULL;
    }

    struct sap_guest *g = (struct sap_guest *)calloc(1, sizeof(*g));
    if (g == NULL) {
        set_error(error, cap, "out of memory");
        return NULL;
    }
    g->post = cfg->post;
    g->userdata = cfg->userdata;

    if (read_file(cfg->image_path, &g->blob, &g->blob_len, error, cap) != 0) {
        free(g);
        return NULL;
    }

    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &g->uc);
    if (err != UC_ERR_OK) {
        set_error(error, cap, "cannot open unicorn engine: %s", uc_strerror(err));
        free(g->blob);
        free(g);
        return NULL;
    }

    if (load_segments(g, error, cap) != 0 ||
        load_scratch(g, error, cap) != 0 ||
        load_tables(g, error, cap) != 0 ||
        load_trampoline(g, error, cap) != 0) {
        uc_close(g->uc);
        free(g->blob);
        free(g);
        return NULL;
    }
    return g;
}

void sap_guest_free(sap_guest *g)
{
    if (g == NULL) {
        return;
    }
    if (g->uc != NULL) {
        uc_close(g->uc);
    }
    free(g->blob);
    free(g);
}

void sap_guest_get_stats(const sap_guest *g, sap_guest_stats *out)
{
    if (g == NULL || out == NULL) {
        return;
    }
    *out = g->stats;
}

/* Filled in by the next block, once the import, rebase and bind tables are
 * parsed and the shim layer exists. */
int sap_guest_handshake(sap_guest *g, char *error, size_t cap)
{
    (void)g;
    set_error(error, cap, "not implemented yet");
    return -1;
}

int sap_guest_sign(sap_guest *g, const uint8_t *body, size_t body_len,
                   char **header, char *error, size_t cap)
{
    (void)g;
    (void)body;
    (void)body_len;
    (void)header;
    set_error(error, cap, "not implemented yet");
    return -1;
}
