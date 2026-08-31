/*
 * client.h — SSH client: auth + channel session
 */
#ifndef SSH_CLIENT_H
#define SSH_CLIENT_H

#include "transport.h"

/* run a command via shell (interactive plumbing).
 * in_fn/out_fn: optional callbacks, NULL = /dev/null style.
 * If cmd is NULL, requests an interactive shell.
 * Returns 0 when the channel closes cleanly, -1 on error. */
int sshe_client_run(sshe_tx *t,
                    const char *user, const char *pass, const char *cmd,
                    int (*out_fn)(void *ctx, const unsigned char *d, size_t n),
                    void *out_ctx,
                    int (*in_fn)(void *ctx, unsigned char *d, size_t n),
                    void *in_ctx);

#endif