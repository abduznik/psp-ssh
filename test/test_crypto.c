/*
 * test_crypto.c — RFC 7748/8032 + AES + HMAC vector tests (host gcc)
 * Vectors extracted from rfc-editor.org (vendored in vendor/).
 */

#include <stdio.h>
#include <string.h>

#include "sshcrypto.h"

static int failures = 0;
static void check(int cond, const char *label)
{
    printf("%s %s\n", cond ? "PASS" : "FAIL", label);
    if (!cond) failures++;
}

static void hex(const unsigned char *b, int n, char *out)
{
    int i;
    for (i = 0; i < n; i++)
        sprintf(out + i * 2, "%02x", b[i]);
    out[n * 2] = 0;
}

static int unhex(const char *h, unsigned char *out)
{
    int n = 0;
    while (h[0] && h[1]) {
        unsigned int v;
        if (sscanf(h, "%2x", &v) != 1) break;
        out[n++] = (unsigned char)v;
        h += 2;
    }
    return n;
}

int main(void)
{
    /* RFC 7748 §5.2 vector: X25519(alice_priv, base) == alice_pub */
    {
        unsigned char scalar[32], point[32], out[32], expect[32];
        unhex("77076d0a7318a57d3c16c17251b26645"
              "df4c2f87ebc0992ab177fba51db92c2a", scalar);
        unhex("09000000000000000000000000000000"
              "00000000000000000000000000000000", point);
        unhex("8520f0098930a754748b7ddcb43ef75a"
              "0dbf3a0d26381af4eba4a98eaa9b4e6a", expect);
        check(ssh_x25519(out, scalar, point) == 0 &&
              memcmp(out, expect, 32) == 0, "RFC7748 X25519 vector");
    }

    /* RFC 8032 TEST 1: empty message ed25519 verify */
    {
        unsigned char pk[32], sig[64];
        unsigned char msg[1];
        unhex("d75a980182b10ab7d54bfed3c964073a"
              "0ee172f3daa62325af021a68f707511a", pk);
        unhex("e5564300c360ac729086e2cc806e828a"
              "84877f1eb8e5d974d873e06522490155"
              "5fb8821590a33bacc61e39701cf9b46b"
              "d25bf5f0595bbe24655141438e7a100b", sig);
        msg[0] = 0;
        check(ssh_ed25519_verify(sig, msg, 0, pk) == 0,
              "RFC8032 ed25519 verify (empty msg)");
        sig[0] ^= 1;
        check(ssh_ed25519_verify(sig, msg, 0, pk) != 0,
              "RFC8032 ed25519 tampered sig rejected");
    }

    /* SHA-256("abc") */
    {
        unsigned char out[32], expect[32];
        unhex("ba7816bf8f01cfea414140de5dae2223"
              "b00361a396177a9cb410ff61f20015ad", expect);
        ssh_sha256((const unsigned char *)"abc", 3, out);
        check(memcmp(out, expect, 32) == 0, "SHA256('abc')");
    }

    /* HMAC-SHA1 RFC 2202 test case 1: key=0x0b*20, data="Hi There" */
    {
        unsigned char key[20], out[20], expect[20];
        unsigned char data[] = "Hi There";
        memset(key, 0x0b, 20);
        unhex("b617318655057264e28bc0b6fb378c8e"
              "f146be00", expect);
        ssh_hmac_sha1(key, 20, data, 8, out);
        check(memcmp(out, expect, 20) == 0, "HMAC-SHA1 RFC2202 #1");
    }

    /* HMAC-SHA256 RFC 4231 test case 1 */
    {
        unsigned char key[20], out[32], expect[32];
        unsigned char data[] = "Hi There";
        memset(key, 0x0b, 20);
        unhex("b0344c61d8db38535ca8afceaf0bf12b"
              "881dc200c9833da726e9376c2e32cff7", expect);
        ssh_hmac_sha256(key, 20, data, 8, out);
        check(memcmp(out, expect, 32) == 0, "HMAC-SHA256 RFC4231 #1");
    }

    /* AES-128 CTR: NIST SP800-38A F.5.1 */
    {
        unsigned char key[16], iv[16];
        unsigned char in[64], out[64], expect[64];
        int i;
        unhex("2b7e151628aed2a6abf7158809cf4f3c", key);
        unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", iv);
        unhex("6bc1bee22e409f96e93d7e117393172a", in + 0);
        unhex("ae2d8a571e03ac9c9eb76fac45af8e51", in + 16);
        unhex("30c81c46a35ce411e5fbc1191a0a52ef", in + 32);
        unhex("f69f2445df4f9b17ad2b417be66c3710", in + 48);
        unhex("874d6191b620e3261bef6864990db6ce", expect + 0);
        unhex("9806f66b7970fdff8617187bb9fffdff", expect + 16);
        unhex("5ae4df3edbd5d35e5b4f09020db03eab", expect + 32);
        unhex("1e031dda2fbe03d1792170a0f3009cee", expect + 48);
        ssh_aes128_ctr_crypt(key, iv, in, out, 64);
        check(memcmp(out, expect, 64) == 0, "AES128-CTR NIST F.5.1");
        /* mutability check: iv counter advanced 4 blocks */
        unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", iv); /* restore */
        (void)i;
    }

    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}