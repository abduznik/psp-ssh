/*
 * client.c — userauth (RFC 4252) + connection/session (RFC 4254)
 *
 * Lean M1: password auth only; one "session" channel; optional
 * pty-req then exec/shell; data pump between callbacks.
 */

#include <stdlib.h>
#include <string.h>

#include "client.h"

#define MSG_SERVICE_REQUEST  5
#define MSG_SERVICE_ACCEPT   6
#define MSG_DISCONNECT       1
#define MSG_IGNORE           2
#define MSG_UNIMPLEMENTED    3
#define MSG_DEBUG            4

#define MSG_USERAUTH_REQUEST        50
#define MSG_USERAUTH_FAILURE        51
#define MSG_USERAUTH_SUCCESS        52
#define MSG_USERAUTH_BANNER         53

#define MSG_CHANNEL_OPEN            90
#define MSG_CHANNEL_OPEN_CONFIRMATION 91
#define MSG_CHANNEL_OPEN_FAILURE    92
#define MSG_CHANNEL_WINDOW_ADJUST   93
#define MSG_CHANNEL_DATA            94
#define MSG_CHANNEL_EXTENDED_DATA   95
#define MSG_CHANNEL_EOF             96
#define MSG_CHANNEL_CLOSE           97
#define MSG_CHANNEL_REQUEST         98
#define MSG_CHANNEL_SUCCESS         99
#define MSG_CHANNEL_FAILURE        100

#define WIN_SIZE 131072

/* wait for a specific message type, discarding banners/ignores/debug.
 * returns 0 and payload in out, or -1. */
static int expect_msg(sshe_tx *t, int want, sshe_buf *out)
{
    for (;;) {
        int r;
        out->len = 0;
        out->pos = 0;
        r = sshe_tx_recv_packet(t, out);
        if (r < 0) return -1;
        if (r == want) return 0;
        if (r == MSG_USERAUTH_BANNER || r == MSG_IGNORE ||
            r == MSG_DEBUG || r == MSG_UNIMPLEMENTED) {
            continue; /* skip noise */
        }
        if (r == MSG_DISCONNECT) return -1;
        return -1; /* unexpected */
    }
}

/* ── auth: none -> password ── */
static int do_auth(sshe_tx *t, const char *user, const char *pass)
{
    sshe_buf msg = {0};
    sshe_buf out = {0};

    /* service request */
    sshe_buf_u8(&msg, MSG_SERVICE_REQUEST);
    sshe_buf_str(&msg, "ssh-userauth", 12);
    if (sshe_tx_send_payload(t, &msg) != 0) { sshe_buf_free(&msg); return -1; }
    if (expect_msg(t, MSG_SERVICE_ACCEPT, &out) != 0) {
        sshe_buf_free(&msg);
        sshe_buf_free(&out);
        return -1;
    }

    /* password auth request */
    msg.len = 0; msg.pos = 0;
    sshe_buf_u8(&msg, MSG_USERAUTH_REQUEST);
    sshe_buf_str(&msg, user, strlen(user));
    sshe_buf_str(&msg, "ssh-connection", 14);
    sshe_buf_str(&msg, "password", 8);
    sshe_buf_u8(&msg, 0); /* FALSE: no new password */
    sshe_buf_str(&msg, pass, strlen(pass));
    if (sshe_tx_send_payload(t, &msg) != 0) { sshe_buf_free(&msg); return -1; }

    if (expect_msg(t, MSG_USERAUTH_SUCCESS, &out) != 0) {
        sshe_buf_free(&msg);
        sshe_buf_free(&out);
        return -1;   /* failure or banner loop exhausted */
    }

    sshe_buf_free(&msg);
    sshe_buf_free(&out);
    return 0;
}

/* ── open session channel, request exec/shell, pump data ── */
int sshe_client_run(sshe_tx *t,
                    const char *user, const char *pass, const char *cmd,
                    int (*out_fn)(void *ctx, const unsigned char *d, size_t n),
                    void *out_ctx,
                    int (*in_fn)(void *ctx, unsigned char *d, size_t n),
                    void *in_ctx)
{
    sshe_buf msg = {0};
    sshe_buf out = {0};
    uint32_t chan = 1;
    uint32_t server_chan = 0;
    int want_reply;

    (void)chan;

    if (do_auth(t, user, pass) != 0) return -1;

    /* channel open: "session" */
    sshe_buf_u8(&msg, MSG_CHANNEL_OPEN);
    sshe_buf_str(&msg, "session", 7);
    sshe_buf_u32(&msg, 1);            /* sender channel */
    sshe_buf_u32(&msg, WIN_SIZE);
    sshe_buf_u32(&msg, 32768);        /* max packet */
    if (sshe_tx_send_payload(t, &msg) != 0) return -1;
    if (expect_msg(t, MSG_CHANNEL_OPEN_CONFIRMATION, &out) != 0) return -1;
    {
        /* RFC 4254 §5.1: recipient channel, sender channel,
           window, max packet — recipient is OUR channel (1);
           sender is the channel number the server assigned. */
        uint8_t typ;
        uint32_t recip_chan, snd_chan, ws, mp;
        if (sshe_buf_get_u8(&out, &typ) != 0 ||
            sshe_buf_get_u32(&out, &recip_chan) != 0 ||
            sshe_buf_get_u32(&out, &snd_chan) != 0 ||
            sshe_buf_get_u32(&out, &ws) != 0 ||
            sshe_buf_get_u32(&out, &mp) != 0) {
            return -1;
        }
        (void)recip_chan; (void)ws; (void)mp;
        server_chan = snd_chan;
    }

    /* channel request: pty (if interactive) or exec */
    if (cmd == NULL) {
        msg.len = 0; msg.pos = 0;
        sshe_buf_u8(&msg, MSG_CHANNEL_REQUEST);
        sshe_buf_u32(&msg, server_chan);
        sshe_buf_str(&msg, "pty-req", 7);
        sshe_buf_u8(&msg, 1);                      /* want reply */
        sshe_buf_str(&msg, "xterm", 5);
        sshe_buf_u32(&msg, 80);                    /* cols */
        sshe_buf_u32(&msg, 24);                    /* rows */
        sshe_buf_u32(&msg, 0);                     /* width px */
        sshe_buf_u32(&msg, 0);                     /* height px */
        sshe_buf_str(&msg, "", 0);                 /* modes */
        if (sshe_tx_send_payload(t, &msg) != 0) return -1;
        if (expect_msg(t, MSG_CHANNEL_SUCCESS, &out) != 0) return -1;
    }

    msg.len = 0; msg.pos = 0;
    sshe_buf_u8(&msg, MSG_CHANNEL_REQUEST);
    sshe_buf_u32(&msg, server_chan);
    if (cmd) {
        sshe_buf_str(&msg, "exec", 4);
        sshe_buf_u8(&msg, 1);
        sshe_buf_str(&msg, cmd, strlen(cmd));
    } else {
        sshe_buf_str(&msg, "shell", 5);
        sshe_buf_u8(&msg, 0);   /* no reply needed */
    }
    if (sshe_tx_send_payload(t, &msg) != 0) return -1;
    (void)want_reply;

    /* data pump until EOF/close */
    for (;;) {
        int r;
        out.len = 0;
        out.pos = 0;
        r = sshe_tx_recv_packet(t, &out);
        if (r < 0) return -1;
        switch (r) {
        case MSG_CHANNEL_DATA: {
            uint8_t typ;
            uint32_t rc;
            const unsigned char *data;
            size_t dlen;
            if (sshe_buf_get_u8(&out, &typ) != 0 ||
                sshe_buf_get_u32(&out, &rc) != 0 ||
                sshe_buf_get_str(&out, &data, &dlen) != 0)
                return -1;
            if (out_fn) out_fn(out_ctx, data, dlen);
            break;
        }
        case MSG_CHANNEL_EOF:
            /* send our EOF + close, done */
            msg.len = 0; msg.pos = 0;
            sshe_buf_u8(&msg, MSG_CHANNEL_EOF);
            sshe_buf_u32(&msg, server_chan);
            sshe_tx_send_payload(t, &msg);
            msg.len = 0; msg.pos = 0;
            sshe_buf_u8(&msg, MSG_CHANNEL_CLOSE);
            sshe_buf_u32(&msg, server_chan);
            sshe_tx_send_payload(t, &msg);
            return 0;
        case MSG_CHANNEL_CLOSE:
            return 0;
        case MSG_CHANNEL_WINDOW_ADJUST:
            break;
        case MSG_CHANNEL_REQUEST: {
            /* ignore server requests (keepalive etc.) */
            break;
        }
        case MSG_IGNORE:
        case MSG_DEBUG:
        case MSG_UNIMPLEMENTED:
            break;
        default:
            return -1;
        }
        /* interactive stdin: if the callback produced a line/datum,
         * forward it. M1: send whatever in_fn returns, or nothing. */
        if (in_fn && r != MSG_CHANNEL_CLOSE) {
            unsigned char d[256];
            size_t n = (size_t)in_fn(in_ctx, d, sizeof(d));
            if (n > 0) {
                msg.len = 0; msg.pos = 0;
                sshe_buf_u8(&msg, MSG_CHANNEL_DATA);
                sshe_buf_u32(&msg, server_chan);
                sshe_buf_str(&msg, d, n);
                sshe_tx_send_payload(t, &msg);
            }
        }
    }
    return 0;
}