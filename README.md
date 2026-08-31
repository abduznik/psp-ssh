# PSPSH — SSH Client for PSP

The joke, made real: a lean, MIT-sized SSH **client** that runs on a genuine PSP.
The thing the internet said couldn't happen (or at least never shipped).

## What it is

- SSH-2 client for PSP WLAN **infrastructure mode** — connect to your router, ssh to any device on your network (or the internet)
- Full protocol, no libssh: transport (RFC 4253), password auth (RFC 4252), session channels (RFC 4254)
- **curve25519-sha256** key exchange, **ssh-ed25519** host keys, **aes128-ctr**, **hmac-sha2-256** — all modern, all fixed-size math (no RSA bignum pain)
- Crypto built from public-domain sources: [TweetNaCl](https://tweetnacl.cr.yp.to) (curve25519/ed25519), [tiny-AES](https://github.com/kokke/tiny-AES-c), [B-Con SHA](https://github.com/B-Con/crypto-algorithms)
- Around 1500 lines of first-party C for the SSH stack; ~600 lines vendored crypto

## Why it's possible

The PSP firmware ships a **full BSD socket stack** (`sceNetInet`) — no PRX hack needed for TCP. The PSP also has **hardware AES/SHA engines** (`sceUtilsBufferCopyWithRange`) for later. A client sidesteps the two worst PSP problems: no pty to emulate, no daemon to babysit — the remote sshd does the work.

## Fun yes, but is it fast?

KEX handshake on a 333MHz MIPS: a moment (curve25519 + ed25519 are small fixed-size operations, no RSA). After that, AES-128-CTR on a 48MiB/s-capable CPU with a 2-5 Mbit WLAN — interactive shells and file transfers are comfortable.

## Repository layout

```
src/app/main.c          PSP entry: config file -> connect -> exec
src/ssh/net.h           socket abstraction (host <-> PSP)
src/ssh/net_host.c      BSD sockets (for CI testing)
src/ssh/net_psp.c       sceNetInet (real PSP)
src/ssh/transport.c     RFC 4253 transport + curve25519 KEX
src/ssh/client.c        RFC 4252/4254 auth + session channels
src/ssh/buf.c           SSH wire primitives (RFC 4251)
src/crypto/             vendored public-domain crypto + glue
test/                   host-run tests (crypto vectors + real-sshd integration)
```

## How the CI proves it

1. **Crypto vectors** on the host: RFC 7748 X25519, RFC 8032 Ed25519, NIST AES-CTR, RFC 2202/4231 HMAC
2. **Integration**: GitHub Actions installs a *real OpenSSH server*, forces the exact algo set we speak, and runs the **real client code** against it: connect → authenticate → `echo PSPSSH_OK` → assert reply. No mock, no shortcut — the same C the PSP runs.
3. **Build**: `pspdev/pspdev` Docker image compiles the EBOOT.PBP.

## Build

```sh
# host tests
make test

# integration (needs a real sshd on 127.0.0.1:2222)
make test-integration

# PSP EBOOT (needs Docker)
make docker
```

## PSP usage (M1)

Drop `PSPSH/EBOOT.PBP` in `/PSP/GAME/PSPSH/` and write `ms0:/PSP/SYSTEM/pspssh.cfg`:

```
host 192.168.1.50
port 22
user alice
pass secret
cmd uname -a
```

## Roadmap (the fun escalates)

- **M2**: interactive shell over the PSPDisp-style 5x7 font terminal; on-screen keyboard entry for host/user/pass; config UI instead of cfg file
- **M3**: ad-hoc mode tunneling so two PSPs can ssh each other over ad-hoc 802.11b (the truly absurd part)
- **M4**: PSP hardware AES/SHA accelerated cipher; known_hosts TOFU storage

## License

First-party code: MIT. Vendored: TweetNaCl (public domain), tiny-AES (MIT), B-Con crypto-algorithms (public domain).