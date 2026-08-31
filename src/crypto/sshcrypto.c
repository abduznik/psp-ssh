/*
 * sshcrypto.c — glue + self-written pieces (HMAC, AES-CTR, wrappers)
 *
 * Everything here is spec-implemented (RFC 2104, RFC 3686) — no
 * guesswork. Host-testable: no PSP dependencies.
 */

#include <string.h>

#include "sshcrypto.h"

#include "sha256.h"
#include "sha1.h"
#include "aes.h"
#include "tweetnacl.h"

/* ── SHA-256 wrappers (B-Con single-shot) ── */
void ssh_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    SHA256_CTX c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* ── HMAC (RFC 2104) ── */
static void hmac_block(const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen,
                       const uint8_t keyb[64], uint8_t inner[64],
                       uint8_t outer[64], uint8_t out[32], int use_sha256)
{
    uint8_t k[64];
    uint8_t digest[32];
    uint8_t buf[64];
    uint8_t ipad[64], opad[64];
    uint8_t inner_hash[32];
    int i;

    memset(k, 0, sizeof(k));
    if (keylen > 64) {
        if (use_sha256) {
            ssh_sha256(key, keylen, k);
        } else {
            SHA1_CTX c1;
            sha1_init(&c1);
            sha1_update(&c1, key, keylen);
            sha1_final(&c1, k);
        }
    } else {
        memcpy(k, key, keylen);
    }

    for (i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    if (use_sha256) {
        SHA256_CTX c;
        sha256_init(&c);
        sha256_update(&c, ipad, 64);
        sha256_update(&c, msg, msglen);
        sha256_final(&c, inner_hash);
        sha256_init(&c);
        sha256_update(&c, opad, 64);
        sha256_update(&c, inner_hash, 32);
        sha256_final(&c, out);
    } else {
        SHA1_CTX c;
        sha1_init(&c);
        sha1_update(&c, ipad, 64);
        sha1_update(&c, msg, msglen);
        sha1_final(&c, inner_hash);
        sha1_init(&c);
        sha1_update(&c, opad, 64);
        sha1_update(&c, inner_hash, 20);
        sha1_final(&c, out);
    }
}

void ssh_hmac_sha1(const uint8_t *key, size_t keylen,
                   const uint8_t *msg, size_t msglen,
                   uint8_t out[20])
{
    uint8_t tmp[32];
    hmac_block(key, keylen, msg, msglen, NULL, NULL, NULL, tmp, 0);
    memcpy(out, tmp, 20);
}

void ssh_hmac_sha256(const uint8_t *key, size_t keylen,
                     const uint8_t *msg, size_t msglen,
                     uint8_t out[32])
{
    hmac_block(key, keylen, msg, msglen, NULL, NULL, NULL, out, 1);
}

/* ── AES-CTR (RFC 3686 static IV) — counter advanced in place so a
   streamed packet read/decrypt keeps keystream continuity ── */
void ssh_aes128_ctr_crypt(const uint8_t key[16], uint8_t counter[16],
                          const uint8_t *in, uint8_t *out, size_t len)
{
    struct AES_ctx ctx;
    uint8_t stream[16];
    size_t i, block_pos = 0;

    AES_init_ctx(&ctx, key);

    for (i = 0; i < len; i++) {
        if (block_pos == 0) {
            memcpy(stream, counter, 16);
            AES_ECB_encrypt(&ctx, stream); /* in-place */
            /* increment 128-bit counter (big-endian) */
            int j;
            for (j = 15; j >= 0; j--) {
                counter[j]++;
                if (counter[j] != 0) break;
            }
        }
        out[i] = (uint8_t)(in[i] ^ stream[block_pos]);
        block_pos = (block_pos + 1) & 15;
    }
}

/* ── Ed25519 / X25519 wrappers (tweetnacl) ── */
int ssh_ed25519_verify(const uint8_t sig[64], const uint8_t msg[], size_t msglen,
                       const uint8_t pk[32])
{
    /* tweetnacl's crypto_sign_open expects sm = sig(64) || msg and a
     * SEPARATE output buffer (it overwrites sm+32 with pk). */
    uint8_t sm[64 + 512];
    uint8_t m[64 + 512];
    unsigned long long mlen;

    if (msglen > 512) return -1; /* keep scratch bounded */
    memcpy(sm, sig, 64);
    memcpy(sm + 64, msg, msglen);

    return crypto_sign_open(m, &mlen, sm, 64 + msglen, pk);
}

int ssh_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    return crypto_scalarmult(out, scalar, point);
}

/* tweetnacl references randombytes for keypair/box functions that are
 * compiled into the same TU. We only use scalarmult/sign, but the
 * linker still needs the symbol. Route it to our RNG. */
#include "net.h"
void randombytes(unsigned char *x, unsigned long long ylen)
{
    sshe_random_fill(x, (size_t)ylen);
}