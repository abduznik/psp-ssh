/*
 * test_integration.c — full SSH client against a REAL sshd.
 *
 * Runs on the CI host (gcc). Requires:
 *   env SSH_TEST_HOST (default 127.0.0.1)
 *   env SSH_TEST_PORT (default 2222)
 *   env SSH_TEST_USER / SSH_TEST_PASS
 *
 * Connects, authenticates, runs `echo PSPSSH_OK $USER`, and asserts
 * the reply arrives — proving transport+auth+channel all work against
 * OpenSSH, with the exact code the PSP will run.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"
#include "transport.h"
#include "client.h"

static char output[4096];
static size_t out_len = 0;

static int out_fn(void *ctx, const unsigned char *d, size_t n)
{
    (void)ctx;
    if (out_len + n < sizeof(output)) {
        memcpy(output + out_len, d, n);
        out_len += n;
        output[out_len] = 0;
    }
    return 0;
}

int main(void)
{
    const char *host = getenv("SSH_TEST_HOST");
    const char *port_s = getenv("SSH_TEST_PORT");
    const char *user = getenv("SSH_TEST_USER");
    const char *pass = getenv("SSH_TEST_PASS");
    sshe_tx t;
    unsigned short port = 2222;
    int rc = 1;

    if (!host) host = "127.0.0.1";
    if (port_s) port = (unsigned short)atoi(port_s);
    if (!user || !pass) {
        fprintf(stderr, "SSH_TEST_USER/SSH_TEST_PASS required\n");
        return 2;
    }

    memset(&t, 0, sizeof(t));
    if (sshe_net_connect(&t.sock, host, port) != 0) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }
    if (sshe_tx_handshake(&t, "SSH-2.0-PSPSSH_0.1") != 0) {
        fprintf(stderr, "handshake failed\n");
        goto out;
    }
    printf("server: %s\n", t.server_id);

    if (sshe_client_run(&t, user, pass,
                        "echo PSPSSH_OK; whoami; uname -s 2>/dev/null || true",
                        out_fn, NULL, NULL, NULL) != 0) {
        fprintf(stderr, "session failed\n");
        goto out;
    }

    printf("OUTPUT:\n%s\n", output);
    if (strstr(output, "PSPSSH_OK") && strstr(output, user)) {
        printf("INTEGRATION PASS\n");
        rc = 0;
    } else {
        printf("INTEGRATION FAIL\n");
    }

out:
    sshe_net_close(&t.sock);
    return rc;
}