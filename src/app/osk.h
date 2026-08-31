/*
 * osk.h — on-screen keyboard (OSK) single-line input.
 * PSP-only; not used by host builds.
 */
#ifndef PSPSSH_OSK_H
#define PSPSSH_OSK_H

/* Run the OSK. Returns 1 if the user confirmed (out holds the text),
 * 0 if cancelled. desc = field label, initial = pre-fill (may be
 * NULL), out/outlen = destination. */
int osk_input(const char *desc, const char *initial,
              char *out, int outlen);

#endif /* PSPSSH_OSK_H */