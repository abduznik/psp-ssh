/*
 * net_host.c — BSD sockets implementation for host testing/CI.
 * Winsock-compatible so it runs on Windows hosts too (CI + local).
 * The integration test runs the real SSH client against real sshd.
 */

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#else
#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "net.h"

typedef struct {
#ifdef _WIN32
    SOCKET fd;
#else
    int fd;
#endif
} host_impl;

#ifdef _WIN32
#define close_socket(fd) closesocket(fd)
#else
#define close_socket(fd) close(fd)
#endif

static int net_ready(void)
{
#ifdef _WIN32
    static int done = 0;
    if (!done) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
        done = 1;
    }
#endif
    return 0;
}

int sshe_net_connect(sshe_sock *s, const char *host, unsigned short port)
{
    host_impl *h;
    struct addrinfo hints, *res = NULL;
    char portstr[8];
    int r;

    if (net_ready() != 0) return -1;
    h = (host_impl *)calloc(1, sizeof(host_impl));
    if (!h) return -1;
#ifdef _WIN32
    h->fd = INVALID_SOCKET;
#else
    h->fd = -1;
#endif

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%u", port);
    r = getaddrinfo(host, portstr, &hints, &res);
    if (r != 0 || !res) {
        free(h);
        return -1;
    }
    h->fd = (int)socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (h->fd < 0) {
        freeaddrinfo(res);
        free(h);
        return -1;
    }
    r = connect(h->fd, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);
    if (r != 0) {
        close_socket(h->fd);
        free(h);
        return -1;
    }
    s->impl = h;
    return 0;
}

int sshe_net_send(sshe_sock *s, const void *buf, size_t len)
{
    host_impl *h = (host_impl *)s->impl;
#ifdef _WIN32
    return send(h->fd, (const char *)buf, (int)len, 0);
#else
    return (int)send(h->fd, buf, len, 0);
#endif
}

int sshe_net_recv(sshe_sock *s, void *buf, size_t len)
{
    host_impl *h = (host_impl *)s->impl;
#ifdef _WIN32
    return recv(h->fd, (char *)buf, (int)len, 0);
#else
    return (int)recv(h->fd, buf, len, 0);
#endif
}

int sshe_random_fill(unsigned char *buf, size_t n)
{
#ifdef _WIN32
    /* Windows has no /dev/urandom for us here; use a xorshift. */
    static unsigned long long seed = 0x9E3779B97F4A7C15ull;
    size_t i;
    for (i = 0; i < n; i++) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        buf[i] = (unsigned char)(seed >> 33);
    }
    return 0;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got = 0;
    if (!f) return -1;
    got = fread(buf, 1, n, f);
    fclose(f);
    return (got == n) ? 0 : -1;
#endif
}

int sshe_net_close(sshe_sock *s)
{
    host_impl *h = (host_impl *)s->impl;
    if (!h) return -1;
    close_socket(h->fd);
    free(h);
    s->impl = NULL;
    return 0;
}