/*
 * transport.h — SSH-2 transport layer (RFC 4253) + KEX (RFC 8731)
 */
#ifndef SSH_TRANSPORT_H
#define SSH_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include "net.h"
#include "buf.h"

#define SSH_CIPHER_BLOCK 16
#define SSH_MAC_LEN      32      /* hmac-sha2-256 */
#define SSH_IV_LEN       16
#define SSH_KEY_LEN      16      /* aes128-ctr */

/* one direction's crypto state */
typedef struct {
    uint8_t key[SSH_KEY_LEN];
    uint8_t iv[SSH_IV_LEN];      /* also used as mutable CTR counter */
    uint8_t mac_key[SSH_MAC_LEN];
    uint32_t seq;
    int enc;                     /* encryption enabled (after NEWKEYS) */
} sshe_dir;

typedef struct {
    sshe_sock sock;
    sshe_dir c2s;                /* client -> server */
    sshe_dir s2c;                /* server -> client */
    unsigned char session_id[32];
    int have_session_id;
    char server_id[256];
    /* negotiated KEXINIT results */
    uint8_t server_pk[32];       /* ssh-ed25519 host key (raw) */
    int have_server_pk;
} sshe_tx;

/* version + KEXINIT + NEWKEYS: full handshake.
 * Returns 0 ok, -1 on error/failure. */
int sshe_tx_handshake(sshe_tx *t, const char *client_id);

/* send a raw payload (encrypted+MAC'd by current state) */
int sshe_tx_send_payload(sshe_tx *t, sshe_buf *payload);

/* recv one packet, returns message type byte, payload in *out
 * (out->data points to payload only). -1 on error. */
int sshe_tx_recv_packet(sshe_tx *t, sshe_buf *out);

#endif