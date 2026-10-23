#ifndef SAP_GUEST_H
#define SAP_GUEST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The SAP signer, backed by the x86-64 CommerceKit guest running under the
 * Unicorn interpreter. This is the probeapp chain turned into a library: the
 * same loader, the same shim dispatch, the same Objective-C runtime, and the
 * same top-level driver loop for objc_msgSend.
 *
 * Versions are not interchangeable: the certificate leg needs 200 and the
 * reply-consuming leg needs 210. 211 and above fail, so this is an exact
 * match, not a floor. */

typedef struct sap_guest sap_guest;

/* The HTTP round trip between the two exchange calls belongs to the caller:
 * the guest is synchronous and has no network stack. Fill up to reply_cap
 * bytes and store the length in reply_len. Return 0 when the reply is valid;
 * anything else aborts the chain and is returned to the caller. */
typedef int (*sap_post_fn)(const uint8_t *request, size_t request_len,
                           uint8_t *reply, size_t reply_cap, size_t *reply_len,
                           void *userdata);

typedef struct sap_guest_config {
    const char *image_path;       /* X64I container on disk */
    const uint8_t *certificate;   /* decoded sign-sap-setup-cert */
    size_t certificate_len;
    const uint8_t *hardware_id;   /* up to 20 bytes */
    size_t hardware_id_len;
    sap_post_fn post;             /* required: joins the two exchange legs */
    void *userdata;
} sap_guest_config;

/* Returns NULL and fills error when the image cannot be loaded or the
 * hardware block is rejected. */
sap_guest *sap_guest_new(const sap_guest_config *cfg, char *error, size_t error_cap);
void sap_guest_free(sap_guest *guest);

/* Runs certificate leg, HTTP round trip and reply-consuming leg. Returns 0 on
 * success and leaves the signer ready for sap_guest_sign. */
int sap_guest_handshake(sap_guest *guest, char *error, size_t error_cap);

/* Signs body and writes the value of the X-Apple-SAP-Signature header.
 * Returns 0 on success. The caller owns *header and frees it. */
int sap_guest_sign(sap_guest *guest, const uint8_t *body, size_t body_len,
                   char **header, char *error, size_t error_cap);

/* Diagnostics: the version each leg used and the status each returned. */
typedef struct sap_guest_stats {
    uint32_t cert_version;
    int32_t cert_status;
    int32_t cert_state;
    uint32_t reply_version;
    int32_t reply_status;
    int32_t reply_state;
    int32_t attempts;      /* the reply leg often succeeds on the second try */
    size_t signature_len;
    uint32_t imports_served;
    int32_t objc_sends;
    int32_t objc_misses;
    char objc_last_miss[128];
} sap_guest_stats;

void sap_guest_get_stats(const sap_guest *guest, sap_guest_stats *out);

#ifdef __cplusplus
}
#endif

#endif
