/*
 * net_host.c — BSD sockets implementation for host testing/CI.
 * The integration test runs the real SSH client against real sshd.
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "net.h"

typedef struct {
    int fd;
} host_impl;

int sshe_net_connect(sshe_sock *s, const char *host, unsigned short port)
{
    host_impl *h = (host_impl *)calloc(1, sizeof(host_impl));
    struct addrinfo hints, *res = NULL;
    char portstr[8];
    int r;

    if (!h) return -1;
    h->fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%u", port);
    r = getaddrinfo(host, portstr, &hints, &res);
    if (r != 0 || !res) {
        free(h);
        return -1;
    }
    h->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (h->fd < 0) {
        freeaddrinfo(res);
        free(h);
        return -1;
    }
    r = connect(h->fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (r != 0) {
        close(h->fd);
        free(h);
        return -1;
    }
    s->impl = h;
    return 0;
}

int sshe_net_send(sshe_sock *s, const void *buf, size_t len)
{
    host_impl *h = (host_impl *)s->impl;
    return (int)send(h->fd, buf, len, 0);
}

int sshe_net_recv(sshe_sock *s, void *buf, size_t len)
{
    host_impl *h = (host_impl *)s->impl;
    return (int)recv(h->fd, buf, len, 0);
}

int sshe_random_fill(unsigned char *buf, size_t n)
{
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got = 0;
    if (!f) return -1;
    got = fread(buf, 1, n, f);
    fclose(f);
    return (got == n) ? 0 : -1;
}

int sshe_net_close(sshe_sock *s)
{
    host_impl *h = (host_impl *)s->impl;
    if (!h) return -1;
    if (h->fd >= 0) close(h->fd);
    free(h);
    s->impl = NULL;
    return 0;
}