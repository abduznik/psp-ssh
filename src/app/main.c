/*
 * main.c — PSP SSH client UI (M2: on-screen config + shell)
 *
 * - Config menu on the debug screen: D-pad to pick a field, X to
 *   edit it via the system OSK, START (or triangle) to connect.
 * - Optional ms0:/PSP/SYSTEM/pspssh.cfg pre-fills the fields.
 * - With a command set: exec once, print output, return to menu.
 * - Without a command: interactive shell over a pty — X opens the
 *   OSK to type a line, HOME closes the session / exits.
 * - HOME always exits cleanly (no power-cycling to leave).
 */

#include <pspkernel.h>
#include <pspdebug.h>
#include <pspctrl.h>
#include <pspdisplay.h>
#include <pspgu.h>
#include <pspnet.h>
#include <pspnet_inet.h>
#include <pspnet_apctl.h>
#include <psputility.h>
#include <pspwlan.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../ssh/net.h"
#include "../ssh/transport.h"
#include "../ssh/client.h"
#include "osk.h"

PSP_MODULE_INFO("PSPSSH", 0x1000, 0, 2);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER | PSP_THREAD_ATTR_VFPU);
PSP_HEAP_SIZE_KB(8 * 1024);

#define CONFIG "ms0:/PSP/SYSTEM/pspssh.cfg"

/* GU setup for the utility dialogs (OSK). The OSK renders through
   the graphics engine; without sceGuInit the dialog is invisible but
   still accepts input — the classic "hidden keyboard" bug. This
   mirrors the official PSPSDK OSK sample's setup exactly. */
#define BUF_WIDTH   512
#define SCR_WIDTH   480
#define SCR_HEIGHT  272
#define PIXEL_SIZE  4
#define FRAME_SIZE  (BUF_WIDTH * SCR_HEIGHT * PIXEL_SIZE)
static unsigned int __attribute__((aligned(16))) gu_list[262144];

static void gu_init(void)
{
    sceGuInit();
    sceGuStart(GU_DIRECT, gu_list);
    sceGuDrawBuffer(GU_PSM_8888, (void *)0, BUF_WIDTH);
    sceGuDispBuffer(SCR_WIDTH, SCR_HEIGHT, (void *)FRAME_SIZE, BUF_WIDTH);
    sceGuDepthBuffer((void *)(FRAME_SIZE * 2), BUF_WIDTH);
    sceGuOffset(2048 - (SCR_WIDTH / 2), 2048 - (SCR_HEIGHT / 2));
    sceGuViewport(2048, 2048, SCR_WIDTH, SCR_HEIGHT);
    sceGuDepthRange(0xc350, 0x2710);
    sceGuScissor(0, 0, SCR_WIDTH, SCR_HEIGHT);
    sceGuEnable(GU_SCISSOR_TEST);
    sceGuDepthFunc(GU_GEQUAL);
    sceGuEnable(GU_DEPTH_TEST);
    sceGuFrontFace(GU_CW);
    sceGuShadeModel(GU_FLAT);
    sceGuEnable(GU_CULL_FACE);
    sceGuEnable(GU_TEXTURE_2D);
    sceGuEnable(GU_CLIP_PLANES);
    sceGuFinish();
    sceGuSync(GU_SYNC_FINISH, GU_SYNC_WHAT_DONE);
    sceDisplayWaitVblankStart();
    sceGuDisplay(GU_TRUE);
}

static char cfg_host[64] = "";
static unsigned short cfg_port = 22;
static char cfg_user[32] = "";
static char cfg_pass[64] = "";
static char cfg_cmd[256] = "";

/* ── exit via HOME: callback thread + ctrl poll ── */

static int exit_callback(int arg1, int arg2, void *common)
{
    (void)arg1; (void)arg2; (void)common;
    sceKernelExitGame();
    return 0;
}

static int vsh_callback_thread(SceSize args, void *argp)
{
    int cbid;
    (void)args; (void)argp;
    cbid = sceKernelCreateCallback("Exit Callback", exit_callback, NULL);
    sceKernelRegisterExitCallback(cbid);
    sceKernelSleepThreadCB();
    return 0;
}

static void register_exit_callback(void)
{
    int thid = sceKernelCreateThread("exit_cb", vsh_callback_thread,
                                     0x11, 0xFA0, 0, NULL);
    if (thid >= 0) sceKernelStartThread(thid, 0, NULL);
}

/* true when HOME held — polled in tight loops */
static int home_pressed(void)
{
    SceCtrlData pad;
    sceCtrlPeekBufferPositive(&pad, 1);
    return (pad.Buttons & PSP_CTRL_HOME) != 0;
}

/* stall until HOME; used on every exit path */
static void hold(const char *msg)
{
    pspDebugScreenPrintf("%s\n", msg);
    pspDebugScreenPrintf("[HOME] exit\n");
    sceCtrlSetSamplingMode(PSP_CTRL_MODE_DIGITAL);
    while (!home_pressed()) sceKernelDelayThread(100000);
    sceKernelExitGame();
}

/* ── config: load optional pre-fill ── */
static void load_config(void)
{
    FILE *f = fopen(CONFIG, "r");
    char line[300];
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        char key[32], val[240];
        if (sscanf(line, "%31s %239s", key, val) == 2) {
            if (strcmp(key, "host") == 0)      snprintf(cfg_host, sizeof(cfg_host), "%s", val);
            else if (strcmp(key, "port") == 0) cfg_port = (unsigned short)atoi(val);
            else if (strcmp(key, "user") == 0) snprintf(cfg_user, sizeof(cfg_user), "%s", val);
            else if (strcmp(key, "pass") == 0) snprintf(cfg_pass, sizeof(cfg_pass), "%s", val);
            else if (strcmp(key, "cmd") == 0)  snprintf(cfg_cmd, sizeof(cfg_cmd), "%s", val);
        }
    }
    fclose(f);
}

/* ── network init: load modules first (the whole point) ── */
static int load_net_modules(void)
{
    const struct { unsigned int type; const char *name; } mods[] = {
        { PSP_NET_MODULE_COMMON,   "COMMON"   },
        { PSP_NET_MODULE_INET,     "INET"     },
        { PSP_NET_MODULE_PARSEURI, "PARSEURI" },
        { PSP_NET_MODULE_PARSEHTTP,"PARSEHTTP"},
        { PSP_NET_MODULE_HTTP,     "HTTP"     },
        { PSP_NET_MODULE_SSL,      "SSL"      },
    };
    int i;
    for (i = 0; i < (int)(sizeof(mods) / sizeof(mods[0])); i++) {
        int err = sceUtilityLoadNetModule(mods[i].type);
        if (err < 0 && err != 0x80010003) {   /* already loaded: ok */
            pspDebugScreenPrintf("load %s: 0x%08X\n", mods[i].name, err);
            return -1;
        }
    }
    return 0;
}

static int init_net(void)
{
    int err;
    if (load_net_modules() != 0) return -1;
    err = sceNetInit(0x80000, 42, 0, 42, 0);
    if (err != 0) { pspDebugScreenPrintf("sceNetInit: 0x%08X\n", err); return -1; }
    err = sceNetInetInit();
    if (err != 0) { pspDebugScreenPrintf("sceNetInetInit: 0x%08X\n", err); return -1; }
    err = sceNetApctlInit(0x8000, 48);
    if (err != 0) { pspDebugScreenPrintf("sceNetApctlInit: 0x%08X\n", err); return -1; }
    return 0;
}

/* Print the PSP's own WLAN identity — proves which subnet we're on
   and exposes guest-network isolation instantly. */
static void net_info(void)
{
    union SceNetApctlInfo info;

    if (sceNetApctlGetInfo(PSP_NET_APCTL_INFO_IP, &info) == 0)
        pspDebugScreenPrintf("psp ip : %s\n", info.ip);
    else
        pspDebugScreenPrintf("psp ip : (none)\n");
    if (sceNetApctlGetInfo(PSP_NET_APCTL_INFO_SUBNETMASK, &info) == 0)
        pspDebugScreenPrintf("psp msk: %s\n", info.subNetMask);
    if (sceNetApctlGetInfo(PSP_NET_APCTL_INFO_GATEWAY, &info) == 0)
        pspDebugScreenPrintf("psp gw : %s\n", info.gateway);
    if (sceNetApctlGetInfo(PSP_NET_APCTL_INFO_SSID, &info) == 0)
        pspDebugScreenPrintf("psp ssid: %s\n", info.ssid);
    if (sceNetApctlGetInfo(PSP_NET_APCTL_INFO_PRIMDNS, &info) == 0)
        pspDebugScreenPrintf("psp dns : %s\n", info.primaryDns);
}

/* Drive the WLAN association from inside the app. The XMB-side
   connection does NOT survive into homebrew ("psp ip: (none)" on the
   field test) — every homebrew must connect via sceNetApctlConnect(0)
   (index 0 = the saved XMB profile) and wait for GOT_IP. Returns 0 on
   success. */
static int apctl_connect(void)
{
    const char *names[] = {
        "DISCONNECTED", "SCANNING", "JOINING", "GETTING_IP",
        "GOT_IP", "EAP_AUTH", "KEY_EXCHANGE"
    };
    int state = PSP_NET_APCTL_STATE_DISCONNECTED;
    int i;

    if (!sceWlanDevIsPowerOn()) {
        pspDebugScreenPrintf("warn: wlan power off (switch?)\n");
        return -1;
    }

    if (sceNetApctlConnect(0) != 0) {
        pspDebugScreenPrintf("apctl connect failed\n");
        return -1;
    }

    pspDebugScreenPrintf("wlan: connecting...\n");
    for (i = 0; i < 75; i++) {              /* up to ~15 s */
        if (sceNetApctlGetState(&state) != 0) {
            pspDebugScreenPrintf("apctl getstate failed\n");
            return -1;
        }
        if (state == PSP_NET_APCTL_STATE_GOT_IP)
            break;
        if (state == PSP_NET_APCTL_STATE_DISCONNECTED &&
            i > 5) {
            pspDebugScreenPrintf("apctl: dropped to DISCONNECTED\n");
            return -1;
        }
        pspDebugScreenPrintf("  state %d %-11s\r", state,
                             names[state < 7 ? state : 6]);
        sceKernelDelayThread(200000);       /* 200 ms */
    }
    pspDebugScreenPrintf("\n");
    if (state != PSP_NET_APCTL_STATE_GOT_IP) {
        pspDebugScreenPrintf("wlan: no IP in %d s (state %d)\n", 15, state);
        return -1;
    }
    pspDebugScreenPrintf("wlan: GOT_IP\n");
    return 0;
}

/* ── session output: render remote bytes to the debug screen,
      stripping CR and control bytes we cannot show ── */
static int out_print(void *ctx, const unsigned char *d, size_t n)
{
    size_t i;
    char line[256];
    size_t li = 0;
    (void)ctx;
    for (i = 0; i < n; i++) {
        unsigned char c = d[i];
        if (c == '\r') continue;
        if (c == '\n') {
            line[li] = 0;
            pspDebugScreenPrintf("%s\n", line);
            li = 0;
            continue;
        }
        if (c < 0x20 || c >= 0x7F) continue;   /* skip ESC/osc etc. */
        if (li < sizeof(line) - 1) line[li++] = (char)c;
    }
    if (li > 0) {
        line[li] = 0;
        pspDebugScreenPrintf("%s", line);
    }
    return 0;
}

/* ── session input: X opens OSK, returns one line (with \n) ── */
static char pending[256];
static int have_pending;

static int in_line(void *ctx, unsigned char *d, size_t n)
{
    size_t len;
    (void)ctx;
    if (!have_pending) {
        SceCtrlData pad;
        sceCtrlPeekBufferPositive(&pad, 1);
        if (pad.Buttons & PSP_CTRL_CROSS) {
            char raw[240];
            memset(raw, 0, sizeof(raw));
            if (osk_input("command", "", raw, sizeof(raw)) &&
                raw[0]) {
                snprintf(pending, sizeof(pending), "%s\n", raw);
                have_pending = 1;
            }
        }
    }
    if (!have_pending) return 0;
    len = strlen(pending);
    if (len > n) len = n;
    memcpy(d, pending, len);
    /* consume only the bytes handed out */
    if (len == strlen(pending)) have_pending = 0;
    else memmove(pending, pending + len, strlen(pending + len) + 1);
    return (int)len;
}

/* ── config menu ── */
enum { F_HOST, F_PORT, F_USER, F_PASS, F_CMD, F_COUNT };

static const char *field_names[F_COUNT] = {
    "host", "port", "user", "pass", "cmd"
};

static void menu_render(int sel)
{
    char pb[80];
    int i;
    pspDebugScreenClear();
    pspDebugScreenPrintf("PSPSSH v0.2 - SSH client\n");
    pspDebugScreenPrintf("------------------------\n");
    for (i = 0; i < F_COUNT; i++) {
        const char *val;
        if (i == F_PORT) {
            snprintf(pb, sizeof(pb), "%u", (unsigned)cfg_port);
            val = pb;
        } else if (i == F_PASS) {
            val = cfg_pass[0] ? "******" : "";
        } else if (i == F_HOST) val = cfg_host;
        else if (i == F_USER) val = cfg_user;
        else val = cfg_cmd;
        pspDebugScreenPrintf("%c %-5s %s\n",
                             i == sel ? '>' : ' ', field_names[i], val);
    }
    pspDebugScreenPrintf("------------------------\n");
    pspDebugScreenPrintf("X edit  START connect  HOME exit\n");
    pspDebugScreenPrintf("(cmd empty = interactive shell)\n");
}

static int menu_run(void)
{
    int sel = 0;
    SceCtrlData pad, old;
    memset(&old, 0, sizeof(old));
    sceCtrlSetSamplingMode(PSP_CTRL_MODE_DIGITAL);
    menu_render(sel);
    for (;;) {
        char buf[300];
        if (home_pressed()) return -2;               /* exit app */
        sceCtrlPeekBufferPositive(&pad, 1);
        if ((pad.Buttons & PSP_CTRL_UP) && !(old.Buttons & PSP_CTRL_UP)) {
            sel = (sel + F_COUNT - 1) % F_COUNT;
            menu_render(sel);
        }
        if ((pad.Buttons & PSP_CTRL_DOWN) && !(old.Buttons & PSP_CTRL_DOWN)) {
            sel = (sel + 1) % F_COUNT;
            menu_render(sel);
        }
        if ((pad.Buttons & PSP_CTRL_CROSS) && !(old.Buttons & PSP_CTRL_CROSS)) {
            const char *cur = NULL;
            switch (sel) {
            case F_HOST: cur = cfg_host; break;
            case F_PORT: snprintf(buf, sizeof(buf), "%u", (unsigned)cfg_port); cur = buf; break;
            case F_USER: cur = cfg_user; break;
            case F_PASS: cur = cfg_pass; break;
            case F_CMD:  cur = cfg_cmd;  break;
            }
            if (osk_input(field_names[sel], cur, buf, sizeof(buf))) {
                switch (sel) {
                case F_HOST: snprintf(cfg_host, sizeof(cfg_host), "%s", buf); break;
                case F_PORT: cfg_port = (unsigned short)atoi(buf); break;
                case F_USER: snprintf(cfg_user, sizeof(cfg_user), "%s", buf); break;
                case F_PASS: snprintf(cfg_pass, sizeof(cfg_pass), "%s", buf); break;
                case F_CMD:  snprintf(cfg_cmd, sizeof(cfg_cmd), "%s", buf); break;
                }
            }
            menu_render(sel);
        }
        if ((pad.Buttons & (PSP_CTRL_START | PSP_CTRL_TRIANGLE)) &&
            !(old.Buttons & (PSP_CTRL_START | PSP_CTRL_TRIANGLE))) {
            if (!cfg_host[0] || !cfg_user[0]) {
                pspDebugScreenClear();
                pspDebugScreenPrintf("host and user required\n");
                sceKernelDelayThread(1200000);
                menu_render(sel);
            } else {
                return 0;                              /* go connect */
            }
        }
        old = pad;
        sceKernelDelayThread(60000);
    }
}

int main(void)
{
    sshe_tx t;
    int rc;

    pspDebugScreenInit();
    register_exit_callback();
    pspDebugScreenPrintf("PSPSSH v0.2\n");

    load_config();
    rc = menu_run();
    if (rc == -2) { sceKernelExitGame(); return 0; }

    pspDebugScreenClear();
    pspDebugScreenPrintf("connecting to %s:%u as %s ...\n",
                         cfg_host, (unsigned)cfg_port, cfg_user);
    pspDebugScreenPrintf("------------------------\n");

    if (init_net() != 0) {
        hold("net init failed");
    }
    if (apctl_connect() != 0) {
        hold("wlan connect failed");
    }
    net_info();
    pspDebugScreenPrintf("------------------------\n");

    memset(&t, 0, sizeof(t));
    if (sshe_net_connect(&t.sock, cfg_host, cfg_port) != 0) {
        pspDebugScreenPrintf("connect failed (err %d)\n", sshe_net_errno(&t.sock));
        hold("");
    }

    if (sshe_tx_handshake(&t, "SSH-2.0-PSPSSH_0.1") != 0) {
        sshe_net_close(&t.sock);
        hold("handshake failed");
    }
    pspDebugScreenPrintf("connected: %s\n", t.server_id);
    pspDebugScreenPrintf("host key: %02x%02x%02x%02x...\n",
                         t.server_pk[0], t.server_pk[1],
                         t.server_pk[2], t.server_pk[3]);

    if (cfg_cmd[0]) {
        /* exec once */
        pspDebugScreenPrintf("exec: %s\n", cfg_cmd);
        rc = sshe_client_run(&t, cfg_user, cfg_pass, cfg_cmd[0] ? cfg_cmd : NULL,
                             out_print, NULL, NULL, NULL);
    } else {
        /* interactive shell */
        pspDebugScreenPrintf("shell: X types, HOME exits\n");
        have_pending = 0;
        rc = sshe_client_run(&t, cfg_user, cfg_pass, NULL,
                             out_print, NULL, in_line, NULL);
    }

    sshe_net_close(&t.sock);
    if (rc == 0) {
        pspDebugScreenPrintf("\nsession closed\n");
        sceKernelDelayThread(1500000);
    }
    hold(rc == 0 ? "back to menu: restart app" : "session failed");
    sceKernelExitGame();
    return 0;
}