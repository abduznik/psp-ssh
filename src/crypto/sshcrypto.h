/*
 * sshcrypto.h — glue over vendored public-domain crypto for SSH
 *
 * Vendored: tweetnacl (curve25519, ed25519, sha512 — public domain),
 * tiny-AES (kokke, MIT), sha1/sha256 (B-Con, public domain).
 * This file: HMAC (spec-defined), SHA-256 convenience, AES-CTR mode.
 */

#ifndef SSHCRYPTO_H
#define SSHCRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* ── SHA-256 (B-Con) ── */
void ssh_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
int  ssh_sha256_init_ctx(void *ctx); /* opaque sha256_ctx */
void ssh_sha256_update(void *ctx, const uint8_t *data, size_t len);
void ssh_sha256_final(void *ctx, uint8_t out[32]);

/* ── HMAC-SHA1 / HMAC-SHA256 (RFC 2104) ── */
void ssh_hmac_sha1(const uint8_t *key, size_t keylen,
                   const uint8_t *msg, size_t msglen,
                   uint8_t out[20]);
void ssh_hmac_sha256(const uint8_t *key, size_t keylen,
                     const uint8_t *msg, size_t msglen,
                     uint8_t out[32]);

/* ── AES-CTR (RFC 3686 style, MUTABLE counter for streamed decrypt) ── */
void ssh_aes128_ctr_crypt(const uint8_t key[16], uint8_t counter[16],
                          const uint8_t *in, uint8_t *out, size_t len);

/* ── Ed25519 (tweetnacl) ── */
/* verify sig over msg with pk; returns 0 on valid, -1 invalid */
int ssh_ed25519_verify(const uint8_t sig[64], const uint8_t msg[], size_t msglen,
                       const uint8_t pk[32]);

/* ── X25519 (tweetnacl) ── */
int ssh_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

#endif /* SSHCRYPTO_H */