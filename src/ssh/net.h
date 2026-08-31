/*
 * net.h — socket abstraction so the SSH core is host-testable.
 *
 * On PSP these map to sceNetInet (net_psp.c); on the host they are
 * plain BSD sockets (net_host.c). The core code never touches either.
 */

#ifndef SSH_NET_H
#define SSH_NET_H

#include <stddef.h>

typedef struct sshe_sock sshe_sock;
struct sshe_sock { void *impl; };

/* Connect to host:port. Returns 0 ok, -1 error. */
int sshe_net_connect(sshe_sock *s, const char *host, unsigned short port);

/* Last socket error code (errno / sceNetInetGetErrno). */
int sshe_net_errno(sshe_sock *s);

/* Wait up to ms for readability. 1 = readable, 0 = timeout, -1 = err. */
int sshe_net_poll(sshe_sock *s, int ms);

/* Raw byte transports. Return bytes done or -1. */
int sshe_net_send(sshe_sock *s, const void *buf, size_t len);
int sshe_net_recv(sshe_sock *s, void *buf, size_t len);

/* Fill buf with n random bytes (crypto-grade where possible). */
int sshe_random_fill(unsigned char *buf, size_t n);

/* close / teardown */
int sshe_net_close(sshe_sock *s);

#endif /* SSH_NET_H */