/*
 * transport.c — SSH-2 transport layer (RFC 4253) + curve25519 KEX
 *
 * Negotiation (M1 lean set):
 *   kex      : curve25519-sha256  (RFC 8731; also accepts ...@libssh.org
 *   host key : ssh-ed25519
 *   cipher   : aes128-ctr
 *   mac      : hmac-sha2-256
 *   compress : none
 *
 * Packet format (RFC 4253 §6): the MAC covers the PLAINTEXT packet
 * (seq || length || padlen || payload || padding); encryption covers
 * everything except the MAC. AES-CTR is a stream cipher, so we can
 * decrypt the length field as it arrives, then the body, with one
 * ongoing counter per direction.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "transport.h"
#include "sshcrypto.h"

/* debug trace: PSPSH_DEBUG=1 prints protocol events to stderr */
static int dbg_on(void)
{
    static int v = -1;
    if (v < 0) v = getenv("PSPSH_DEBUG") && getenv("PSPSH_DEBUG")[0] == '1';
    return v;
}
#define DBG(...) do { if (dbg_on()) fprintf(stderr, "[pspssh] " __VA_ARGS__); } while (0)

/* PSPSH_HASHDUMP=path dumps every exchange-hash ingredient as
   length-prefixed hex lines for offline ground-truth verification. */
static FILE *dump_fp(void)
{
    static FILE *f = NULL;
    if (!f) {
        const char *p = getenv("PSPSH_HASHDUMP");
        if (p) f = fopen(p, "wb");
    }
    return f;
}
static void dump_tag(const char *tag, const void *data, size_t len)
{
    FILE *f = dump_fp();
    size_t i;
    if (!f) return;
    fprintf(f, "%s %zu ", tag, len);
    for (i = 0; i < len; i++)
        fprintf(f, "%02x", ((const unsigned char *)data)[i]);
    fprintf(f, "\n");
}

/* SSH message numbers */
#define MSG_DISCONNECT       1
#define MSG_IGNORE           2
#define MSG_UNIMPLEMENTED    3
#define MSG_DEBUG            4
#define MSG_SERVICE_REQUEST  5
#define MSG_SERVICE_ACCEPT   6
#define MSG_KEXINIT         20
#define MSG_NEWKEYS         21
#define MSG_KEX_ECDH_INIT   30
#define MSG_KEX_ECDH_REPLY  31

static const char *kex_algs[] = {
    "curve25519-sha256", "curve25519-sha256@libssh.org", NULL
};
static const char *hostkey_algs[] = { "ssh-ed25519", NULL };
static const char *cipher_algs[] = { "aes128-ctr", NULL };
static const char *mac_algs[] = { "hmac-sha2-256", NULL };

static int raw_send(sshe_tx *t, const void *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        int n = sshe_net_send(&t->sock, (const unsigned char *)buf + off,
                              len - off);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int raw_recv(sshe_tx *t, void *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        int n = sshe_net_recv(&t->sock, (unsigned char *)buf + off, len - off);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

/* does server's name-list (raw, starting at pos) contain our pref? */
static int namelist_has(const unsigned char *nl, size_t nl_len, const char *want)
{
    size_t i = 0;
    size_t wl = strlen(want);
    while (i < nl_len) {
        size_t j = i;
        while (j < nl_len && nl[j] != ',') j++;
        if (j - i == wl && memcmp(nl + i, want, wl) == 0) return 1;
        i = j + 1;
    }
    return 0;
}

/* ── send one packet (encrypted + MAC'd per current state) ── */
int sshe_tx_send_payload(sshe_tx *t, sshe_buf *payload)
{
    size_t pay_len = payload->len;
    size_t pad, total, i;
    unsigned char *packet;
    unsigned char mac[SSH_MAC_LEN];
    unsigned char seqbuf[4];
    uint32_t s;

    pad = 16 - ((pay_len + 5) % 16); /* -> mult of 16 after +4+1 */
    if (pad < 4) pad += 16;

    total = 4 + 1 + pay_len + pad;

    packet = (unsigned char *)malloc(total);
    if (!packet) return -1;

    packet[0] = (unsigned char)((pay_len + 1 + pad) >> 24);
    packet[1] = (unsigned char)((pay_len + 1 + pad) >> 16);
    packet[2] = (unsigned char)((pay_len + 1 + pad) >> 8);
    packet[3] = (unsigned char)(pay_len + 1 + pad);
    packet[4] = (unsigned char)pad;
    memcpy(packet + 5, payload->data, pay_len);
    for (i = 0; i < pad; i++) {
        unsigned char r;
        sshe_random_fill(&r, 1);
        packet[5 + pay_len + i] = r;
    }

    /* MAC over PLAINTEXT: seq(4) || packet.
       Pre-NEWKEYS the MAC algorithm is 'none' — no MAC is appended. */
    if (t->c2s.enc) {
        s = t->c2s.seq++;
        seqbuf[0] = (unsigned char)(s >> 24);
        seqbuf[1] = (unsigned char)(s >> 16);
        seqbuf[2] = (unsigned char)(s >> 8);
        seqbuf[3] = (unsigned char)s;
        {
            sshe_buf mb = {0};
            sshe_buf_raw(&mb, seqbuf, 4);
            sshe_buf_raw(&mb, packet, total);
            ssh_hmac_sha256(t->c2s.mac_key, SSH_MAC_LEN, mb.data, mb.len, mac);
            sshe_buf_free(&mb);
        }
    } else {
        t->c2s.seq++;
    }

    if (t->c2s.enc) {
        ssh_aes128_ctr_crypt(t->c2s.key, t->c2s.iv, packet, packet, total);
    }

    if (raw_send(t, packet, total) != 0) {
        free(packet);
        return -1;
    }
    if (t->c2s.enc && raw_send(t, mac, SSH_MAC_LEN) != 0) {
        free(packet);
        return -1;
    }
    free(packet);
    return 0;
}

/* ── receive one packet; on return out contains the payload ──
   returns message type byte, or -1 on error. */
int sshe_tx_recv_packet(sshe_tx *t, sshe_buf *out)
{
    unsigned char first[16];
    unsigned char *body = NULL;
    unsigned char mac[SSH_MAC_LEN];
    unsigned char mac_calc[SSH_MAC_LEN];
    unsigned char seqbuf[4];
    uint32_t packet_len;
    uint32_t s;
    size_t enc_total, rest, pay_len, pad_len;

    out->pos = 0;
    out->len = 0;

    if (raw_recv(t, first, 16) != 0) { DBG("recv: first16 failed\n"); return -1; }
    if (t->s2c.enc) {
        ssh_aes128_ctr_crypt(t->s2c.key, t->s2c.iv, first, first, 16);
    }

    packet_len = ((uint32_t)first[0] << 24) | ((uint32_t)first[1] << 16) |
                 ((uint32_t)first[2] << 8) | (uint32_t)first[3];
    if (packet_len < 4 || packet_len > 35000) {
        DBG("recv: bad packet_len %u\n", packet_len);
        return -1;
    }

    enc_total = (size_t)packet_len + 4;
    rest = enc_total - 16;

    body = (unsigned char *)malloc(rest ? rest : 1);
    if (!body) return -1;
    if (raw_recv(t, body, rest) != 0) { DBG("recv: body failed\n"); free(body); return -1; }
    if (t->s2c.enc) {
        ssh_aes128_ctr_crypt(t->s2c.key, t->s2c.iv, body, body, rest);
    }

    /* pre-NEWKEYS there is no MAC */
    if (t->s2c.enc) {
        unsigned char mac[SSH_MAC_LEN];
        if (raw_recv(t, mac, SSH_MAC_LEN) != 0) { free(body); return -1; }

        /* verify MAC */
        s = t->s2c.seq++;
        seqbuf[0] = (unsigned char)(s >> 24);
        seqbuf[1] = (unsigned char)(s >> 16);
        seqbuf[2] = (unsigned char)(s >> 8);
        seqbuf[3] = (unsigned char)s;
        {
            sshe_buf mb = {0};
            sshe_buf_raw(&mb, seqbuf, 4);
            sshe_buf_raw(&mb, first, 16);
            sshe_buf_raw(&mb, body, rest);
            ssh_hmac_sha256(t->s2c.mac_key, SSH_MAC_LEN, mb.data, mb.len,
                            mac_calc);
            sshe_buf_free(&mb);
        }
        if (memcmp(mac, mac_calc, SSH_MAC_LEN) != 0) {
            DBG("recv: MAC mismatch\n");
            free(body);
            return -1;
        }
    } else {
        t->s2c.seq++;
    }

    /* payload = bytes after [len(4)][padlen(1)] */
    pad_len = first[4];
    if (pad_len == 0 || pad_len > 255 || packet_len < 1 + pad_len) {
        DBG("recv: bad pad_len %lu\n", (unsigned long)pad_len);
        free(body);
        return -1;
    }
    pay_len = (size_t)packet_len - 1 - pad_len;
    if (pay_len <= 16 - 5) {
        sshe_buf_raw(out, first + 5, pay_len);
    } else {
        sshe_buf_raw(out, first + 5, 16 - 5);
        sshe_buf_raw(out, body, pay_len - (16 - 5));
    }

    free(body);
    return out->len ? (int)out->data[0] : -1;
}

static int add_namelist(sshe_buf *b, const char **items)
{
    size_t total = 0;
    int i;
    for (i = 0; items[i]; i++) {
        if (i) total++; /* comma */
        total += strlen(items[i]);
    }
    sshe_buf_u32(b, (uint32_t)total);
    for (i = 0; items[i]; i++) {
        if (i) sshe_buf_raw(b, ",", 1);
        sshe_buf_raw(b, items[i], strlen(items[i]));
    }
    return 0;
}

/* verify the server actually supports our algorithms */
static int check_server_algs(const unsigned char *p, size_t len)
{
    sshe_buf sk = {0};
    uint8_t type;
    size_t nl_len;
    int i;

    sshe_buf_raw(&sk, p, len);
    if (sshe_buf_get_u8(&sk, &type) != 0 || type != MSG_KEXINIT) {
        sshe_buf_free(&sk);
        return -1;
    }
    /* cookie 16 bytes */
    if (sk.pos + 16 > sk.len) { sshe_buf_free(&sk); return -1; }
    sk.pos += 16;

    /* fields in order: kex, hostkey, cipher c2s, cipher s2c,
       mac c2s, mac s2c, comp c2s, comp s2c, langs x2 */
    for (i = 0; i < 8; i++) {
        sshe_buf nl = {0};
        int found = 0;
        if (sshe_buf_get_len(&sk, &nl_len) != 0 ||
            sk.pos + nl_len > sk.len) {
            sshe_buf_free(&sk);
            return -1;
        }
        sshe_buf_raw(&nl, sk.data + sk.pos, nl_len);

        switch (i) {
        case 0: /* kex */
            found = namelist_has(nl.data, nl_len, kex_algs[0]) ||
                    namelist_has(nl.data, nl_len, kex_algs[1]);
            break;
        case 1: /* hostkey */
            found = namelist_has(nl.data, nl_len, hostkey_algs[0]);
            break;
        case 2: case 3: /* cipher */
            found = namelist_has(nl.data, nl_len, cipher_algs[0]);
            break;
        case 4: case 5: /* mac */
            found = namelist_has(nl.data, nl_len, mac_algs[0]);
            break;
        default: /* compression/langs: we only offer none/empty */
            break;
        }
        sshe_buf_free(&nl);
        if (!found && i < 6) {
            sshe_buf_free(&sk);
            return -1;
        }
        sk.pos += nl_len;
    }
    sshe_buf_free(&sk);
    return 0;
}

/* derive one key — RFC 4253 §7.2, OpenSSH kex.c derive_key():
   K1 = HASH(K || H || X || session_id)
   Kn = HASH(K || H || K1 || ... || Kn-1)   (chained, NO counter)
   K is the bignum2 buffer: u32 length + mpint bytes (OpenSSH's
   sshbuf_put_bignum2_bytes) — the same encoding hashed in the
   exchange hash. */
static size_t mpint_encode(unsigned char *out, const uint8_t *in32)
{
    size_t start = 0, len;

    while (start < 32 && in32[start] == 0) start++;
    if (start == 32) { out[0] = 0; return 1; }
    len = 32 - start;
    if (in32[start] & 0x80) {
        out[0] = 0;
        memcpy(out + 1, in32 + start, len);
        return len + 1;
    }
    memcpy(out, in32 + start, len);
    return len;
}

static void derive_key(const uint8_t k_mp[/*up to 33*/], size_t k_len,
                       const uint8_t h[32], char x, const uint8_t sid[32],
                       uint8_t *out, size_t out_len)
{
    uint8_t k_str[4 + 33];      /* u32 len + mpint */
    uint8_t k_str_len;
    uint8_t digest[32];
    size_t got = 0;

    k_str[0] = (uint8_t)(k_len >> 24);
    k_str[1] = (uint8_t)(k_len >> 16);
    k_str[2] = (uint8_t)(k_len >> 8);
    k_str[3] = (uint8_t)k_len;
    memcpy(k_str + 4, k_mp, k_len);
    k_str_len = (uint8_t)(4 + k_len);

    while (got < out_len) {
        sshe_buf hb = {0};
        uint8_t take;

        sshe_buf_raw(&hb, k_str, k_str_len);
        sshe_buf_raw(&hb, h, 32);
        sshe_buf_raw(&hb, &x, 1);
        if (got == 0) {
            sshe_buf_raw(&hb, sid, 32);
        } else {
            sshe_buf_raw(&hb, digest, 32);
        }
        ssh_sha256(hb.data, hb.len, digest);
        sshe_buf_free(&hb);

        take = (uint8_t)(out_len - got);
        if (take > 32) take = 32;
        memcpy(out + got, digest, take);
        got += take;
    }
}

int sshe_tx_handshake(sshe_tx *t, const char *client_id)
{
    sshe_buf kexinit = {0};
    sshe_buf packet = {0};
    sshe_buf server_kex = {0};
    unsigned char cookie[16];
    char idline[256];
    size_t li;
    int r, i;

    /* ---- 1. identification exchange ---- */
    snprintf(idline, sizeof(idline), "%s\r\n", client_id);
    if (raw_send(t, idline, strlen(idline)) != 0) return -1;
    DBG("sent ident %s", client_id);

    li = 0;
    do {
        if (raw_recv(t, &idline[li], 1) != 0) return -1;
    } while (idline[li++] != '\n' && li < sizeof(idline) - 1);
    while (li && (idline[li-1] == '\n' || idline[li-1] == '\r')) idline[--li] = 0;
    memcpy(t->server_id, idline, li + 1);
    DBG("server ident: %s\n", t->server_id);

    /* ---- 2. KEXINIT exchange ---- */
    sshe_random_fill(cookie, 16);
    sshe_buf_u8(&kexinit, MSG_KEXINIT);
    sshe_buf_raw(&kexinit, cookie, 16);
    add_namelist(&kexinit, kex_algs);
    add_namelist(&kexinit, hostkey_algs);
    add_namelist(&kexinit, cipher_algs);
    add_namelist(&kexinit, cipher_algs);
    add_namelist(&kexinit, mac_algs);
    add_namelist(&kexinit, mac_algs);
    sshe_buf_str(&kexinit, "none", 4); /* compression c2s — MUST offer none */
    sshe_buf_str(&kexinit, "none", 4); /* compression s2c */
    sshe_buf_u32(&kexinit, 0);   /* langs c2s */
    sshe_buf_u32(&kexinit, 0);   /* langs s2c */
    sshe_buf_u8(&kexinit, 0);    /* first_kex_packet_follows */
    sshe_buf_u32(&kexinit, 0);   /* reserved */
    DBG("kexinit sent (%d bytes)\n", (int)kexinit.len);

    if (sshe_tx_send_payload(t, &kexinit) != 0) return -1;

    r = sshe_tx_recv_packet(t, &server_kex);
    DBG("server kexinit recv r=%d\n", r);
    if (r != MSG_KEXINIT) return -1;
    if (check_server_algs(server_kex.data, server_kex.len) != 0) {
        DBG("alg check failed\n");
        return -1;
    }
    DBG("alg check ok\n");

    /* ---- 3. ECDH (curve25519) ---- */
    {
        unsigned char eph_sec[32];
        unsigned char base[32];
        unsigned char qc[32];
        memset(base, 0, 32);
        base[0] = 9;

        sshe_random_fill(eph_sec, 32);
        eph_sec[0] &= 248;
        eph_sec[31] &= 127;
        eph_sec[31] |= 64;
        if (ssh_x25519(qc, eph_sec, base) != 0) return -1;
        dump_tag("EPH", eph_sec, 32);

        packet.len = 0; packet.pos = 0;
        sshe_buf_u8(&packet, MSG_KEX_ECDH_INIT);
        sshe_buf_str(&packet, qc, 32);
        if (sshe_tx_send_payload(t, &packet) != 0) return -1;
        DBG("ecdh init sent\n");

        packet.len = 0; packet.pos = 0;
        r = sshe_tx_recv_packet(t, &packet);
        DBG("ecdh reply r=%d\n", r);
        if (r != MSG_KEX_ECDH_REPLY) return -1;

        {
            const unsigned char *ks, *qs, *sig;
            size_t ks_len, qs_len, sig_len;
            unsigned char K[32];
            unsigned char H[32];
            unsigned char eph_sec2[32]; /* for shared secret */
            uint8_t type_b;

            if (sshe_buf_get_u8(&packet, &type_b) != 0 ||
                sshe_buf_get_str(&packet, &ks, &ks_len) != 0 ||
                sshe_buf_get_str(&packet, &qs, &qs_len) != 0 ||
                sshe_buf_get_str(&packet, &sig, &sig_len) != 0) {
                return -1;
            }

            memcpy(eph_sec2, eph_sec, 32);
            if (ssh_x25519(K, eph_sec2, qs) != 0) return -1;

            /* exchange hash — RFC 4253 §7.2 / RFC 8731.
               OpenSSH kexgen.c kex_gen_hash(): EVERY component is a
               string; I_C/I_S are the full KEXINIT payloads (incl.
               type byte); K is the bignum2 buffer hashed as-is —
               which is u32 length + mpint bytes (the shared_secret
               sshbuf produced by kexc25519_shared_key_ext). */
            {
                unsigned char k_mp[33];
                size_t k_len = mpint_encode(k_mp, K);
                size_t vc_len = strlen(client_id);
                size_t vs_len = strlen(t->server_id);
                sshe_buf hb = {0};
                sshe_buf_u32(&hb, (uint32_t)vc_len);
                sshe_buf_raw(&hb, client_id, vc_len);
                sshe_buf_u32(&hb, (uint32_t)vs_len);
                sshe_buf_raw(&hb, t->server_id, vs_len);
                sshe_buf_u32(&hb, (uint32_t)kexinit.len);
                sshe_buf_raw(&hb, kexinit.data, kexinit.len);
                sshe_buf_u32(&hb, (uint32_t)server_kex.len);
                sshe_buf_raw(&hb, server_kex.data, server_kex.len);
                sshe_buf_u32(&hb, (uint32_t)ks_len);
                sshe_buf_raw(&hb, ks, ks_len);
                sshe_buf_u32(&hb, 32);
                sshe_buf_raw(&hb, qc, 32);
                sshe_buf_u32(&hb, (uint32_t)qs_len);
                sshe_buf_raw(&hb, qs, qs_len);
                sshe_buf_u32(&hb, (uint32_t)k_len);
                sshe_buf_raw(&hb, k_mp, k_len);
                ssh_sha256(hb.data, hb.len, H);
                sshe_buf_free(&hb);
                dump_tag("H", H, 32);
            }

            /* parse and verify host key signature */
            {
                sshe_buf kb = {0};
                const unsigned char *alg, *pk, *sigalg, *rawsig;
                size_t alg_len, pk_len, sigalg_len, raw_len;
                unsigned char host_pk[32];
                unsigned char sig_bytes[64];

                sshe_buf_raw(&kb, ks, ks_len);
                if (sshe_buf_get_str(&kb, &alg, &alg_len) != 0 ||
                    sshe_buf_get_str(&kb, &pk, &pk_len) != 0 ||
                    pk_len != 32) {
                    sshe_buf_free(&kb);
                    return -1;
                }
                memcpy(host_pk, pk, 32);
                sshe_buf_free(&kb);

                kb.data = NULL; kb.len = kb.cap = kb.pos = 0;
                sshe_buf_raw(&kb, sig, sig_len);
                if (sshe_buf_get_str(&kb, &sigalg, &sigalg_len) != 0 ||
                    sshe_buf_get_str(&kb, &rawsig, &raw_len) != 0 ||
                    raw_len != 64) {
                    sshe_buf_free(&kb);
                    return -1;
                }
                memcpy(sig_bytes, rawsig, 64);
                sshe_buf_free(&kb);

                dump_tag("SIG", sig_bytes, 64);
                dump_tag("PK", host_pk, 32);

                if (ssh_ed25519_verify(sig_bytes, H, 32, host_pk) != 0) {
                    DBG("host key sig verify FAILED\n");
                    DBG("H: ");
                    for (i = 0; i < 32; i++) DBG("%02x", H[i]);
                    DBG("\nsig: ");
                    for (i = 0; i < 64; i++) DBG("%02x", sig_bytes[i]);
                    DBG("\npk:  ");
                    for (i = 0; i < 32; i++) DBG("%02x", host_pk[i]);
                    DBG("\n");
                    return -1; /* host key signature invalid */
                }
                DBG("host key verified (ed25519)\n");
                memcpy(t->server_pk, host_pk, 32);
                t->have_server_pk = 1;
            }

            /* session id = H on first exchange */
            if (!t->have_session_id) {
                memcpy(t->session_id, H, 32);
                t->have_session_id = 1;
            }

            /* derive IVs, keys, mac keys */
            {
                unsigned char k_mp[33];
                size_t k_len = mpint_encode(k_mp, K);
                derive_key(k_mp, k_len, H, 'A', t->session_id, t->c2s.iv, SSH_IV_LEN);
                derive_key(k_mp, k_len, H, 'B', t->session_id, t->s2c.iv, SSH_IV_LEN);
                derive_key(k_mp, k_len, H, 'C', t->session_id, t->c2s.key, SSH_KEY_LEN);
                derive_key(k_mp, k_len, H, 'D', t->session_id, t->s2c.key, SSH_KEY_LEN);
                derive_key(k_mp, k_len, H, 'E', t->session_id, t->c2s.mac_key, SSH_MAC_LEN);
                derive_key(k_mp, k_len, H, 'F', t->session_id, t->s2c.mac_key, SSH_MAC_LEN);
            }
        }
    }

    /* ---- 4. NEWKEYS ---- */
    {
        sshe_buf nk = {0};
        sshe_buf reply = {0};

        sshe_buf_u8(&nk, MSG_NEWKEYS);
        /* keys are live for c2s only AFTER we send NEWKEYS per RFC:
         * we may switch immediately after sending (server switches
         * when it receives it). Send plaintext NEWKEYS, then flip. */
        if (sshe_tx_send_payload(t, &nk) != 0) {
            sshe_buf_free(&nk);
            return -1;
        }
        t->c2s.enc = 1;

        r = sshe_tx_recv_packet(t, &reply);
        if (r != MSG_NEWKEYS) {
            sshe_buf_free(&nk);
            sshe_buf_free(&reply);
            return -1;
        }
        t->s2c.enc = 1;

        sshe_buf_free(&nk);
        sshe_buf_free(&reply);
    }

    return 0;
}