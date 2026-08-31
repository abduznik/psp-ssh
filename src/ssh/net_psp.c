/*
 * net_psp.c — sceNetInet implementation for the PSP.
 * PSP SDK baby-steps: WLAN on, net module init, sockets, send/recv.
 */

#include <pspkernel.h>
#include <pspnet.h>
#include <pspnet_inet.h>
#include <pspnet_apctl.h>
#include <pspnet_resolver.h>
#include <pspwlan.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"

typedef struct {
    int fd;
} psp_impl;

int sshe_net_connect(sshe_sock *s, const char *host, unsigned short port)
{
    psp_impl *h = (psp_impl *)calloc(1, sizeof(psp_impl));
    struct in_addr addr;

    if (!h) return -1;
    h->fd = -1;

    h->fd = sceNetInetSocket(AF_INET, SOCK_STREAM, 0);
    if (h->fd < 0) { free(h); return -1; }

    addr.s_addr = sceNetInetInetAddr(host);
    if (addr.s_addr == 0xFFFFFFFFu) {
        /* host not dotted-quad — resolve via sceNetResolver (async). 
         * For v0.1 keep it simple: dotted-quad only; DNS lands in M3. */
        sceNetInetClose(h->fd);
        free(h);
        return -1;
    }

    if (sceNetInetConnect(h->fd, &addr, sizeof(addr), port) < 0) {
        sceNetInetClose(h->fd);
        free(h);
        return -1;
    }
    s->impl = h;
    return 0;
}

int sshe_net_send(sshe_sock *s, const void *buf, size_t len)
{
    psp_impl *h = (psp_impl *)s->impl;
    return sceNetInetSend(h->fd, buf, (unsigned int)len, 0);
}

int sshe_net_recv(sshe_sock *s, void *buf, size_t len)
{
    psp_impl *h = (psp_impl *)s->impl;
    return sceNetInetRecv(h->fd, buf, (unsigned int)len, 0);
}

int sshe_random_fill(unsigned char *buf, size_t n)
{
    /* PSP has no /dev/urandom — xorshift seeded from system clock
     * is plenty for the KEXINIT cookie (non-secret). Note in README. */
    static unsigned long long seed = 0;
    unsigned long long x;
    size_t i;
    if (!seed) {
        seed = (unsigned long long)sceKernelGetSystemTimeWide() ^ 0x9E3779B97F4A7C15ull;
    }
    x = seed;
    for (i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        buf[i] = (unsigned char)(x >> 32);
    }
    seed = x;
    return 0;
}

int sshe_net_close(sshe_sock *s)
{
    psp_impl *h = (psp_impl *)s->impl;
    if (!h) return -1;
    if (h->fd >= 0) sceNetInetClose(h->fd);
    free(h);
    s->impl = NULL;
    return 0;
}