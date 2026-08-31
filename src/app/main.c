/*
 * main.c — PSP SSH client entry (M1: config file -> exec -> print)
 *
 * config at ms0:/PSP/SYSTEM/pspssh.cfg, one value per line:
 *   host 192.168.1.10
 *   port 22
 *   user alice
 *   pass secret
 *   cmd  uname -a        (optional; default: no command, exits)
 *
 * M1: wired for testing; the interactive OSK terminal lands in M2/M3.
 */

#include <pspkernel.h>
#include <pspdebug.h>
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

PSP_MODULE_INFO("PSPSSH", 0x1000, 0, 1);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER | PSP_THREAD_ATTR_VFPU);
PSP_HEAP_SIZE_KB(8 * 1024);

#define CONFIG "ms0:/PSP/SYSTEM/pspssh.cfg"

static char cfg_host[64] = "";
static unsigned short cfg_port = 22;
static char cfg_user[32] = "";
static char cfg_pass[64] = "";
static char cfg_cmd[256] = "";

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

/* Load the network modules the PSP ships with. Every homebrew that
   touches the net stack must do this before sceNetInit — calling the
   inits cold just returns errors (and then exiting with a partial
   stack crashes the console). Mirrors pspSdkLoadInetModules()
   (pspsdk src/sdk/inethelper.c). */
static int load_net_modules(void)
{
    const struct { unsigned int type; const char *name; } mods[] = {
        { PSP_NET_MODULE_COMMON,  "COMMON"  },
        { PSP_NET_MODULE_INET,    "INET"    },
        { PSP_NET_MODULE_PARSEURI, "PARSEURI" },
        { PSP_NET_MODULE_PARSEHTTP, "PARSEHTTP" },
        { PSP_NET_MODULE_HTTP,    "HTTP"    },
        { PSP_NET_MODULE_SSL,     "SSL"     },
    };
    int i;
    for (i = 0; i < (int)(sizeof(mods) / sizeof(mods[0])); i++) {
        int err = sceUtilityLoadNetModule(mods[i].type);
        if (err < 0 && err != 0x80010003) { /* 0x80010003 = already loaded */
            pspDebugScreenPrintf("load %s: 0x%08X\n", mods[i].name, err);
            return -1;
        }
    }
    return 0;
}

static int init_net(void)
{
    int err;

    if (load_net_modules() != 0) {
        pspDebugScreenPrintf("net modules failed\n");
        return -1;
    }

    /* SDK-standard arguments (inethelper.c: sceNetInit(0x20000, 0x20,
       0x1000, 0x20, 0x1000) * 2x workspace for our socket buffers) */
    err = sceNetInit(0x80000, 42, 0, 42, 0);
    if (err != 0) { pspDebugScreenPrintf("sceNetInit: 0x%08X\n", err); return -1; }

    err = sceNetInetInit();
    if (err != 0) { pspDebugScreenPrintf("sceNetInetInit: 0x%08X\n", err); return -1; }

    err = sceNetApctlInit(0x8000, 48);
    if (err != 0) { pspDebugScreenPrintf("sceNetApctlInit: 0x%08X\n", err); return -1; }

    return 0;
}

/* Stall instead of returning from main with the net stack up/down —
   exiting mid-stack is what crashed the PSP. Hold until power off. */
static void hold(const char *msg)
{
    pspDebugScreenPrintf("%s\n", msg);
    pspDebugScreenPrintf("hold (power off to exit)\n");
    for (;;) sceKernelDelayThread(1000000);
}

static int out_print(void *ctx, const unsigned char *d, size_t n)
{
    (void)ctx;
    /* raw bytes to stdout — M2 replaces with the PSPSH terminal */
    fwrite(d, 1, n, stdout);
    return 0;
}

int main(void)
{
    sshe_tx t;
    sshe_buf out_ign = {0};

    pspDebugScreenInit();
    pspDebugScreenPrintf("PSPSSH v0.1\n");

    load_config();
    if (!cfg_host[0]) {
        hold("no config at ms0:/PSP/SYSTEM/pspssh.cfg");
    }

    if (init_net() != 0) {
        hold("net init failed");
    }

    memset(&t, 0, sizeof(t));
    if (sshe_net_connect(&t.sock, cfg_host, cfg_port) != 0) {
        hold("connect failed");
    }

    if (sshe_tx_handshake(&t, "SSH-2.0-PSPSSH_0.1") != 0) {
        sshe_net_close(&t.sock);
        hold("handshake failed");
    }
    pspDebugScreenPrintf("connected: %s\n", t.server_id);
    pspDebugScreenPrintf("host key: %02x%02x%02x%02x...\n",
                         t.server_pk[0], t.server_pk[1],
                         t.server_pk[2], t.server_pk[3]);

    if (sshe_client_run(&t, cfg_user, cfg_pass,
                        cfg_cmd[0] ? cfg_cmd : NULL,
                        out_print, NULL, NULL, NULL) != 0) {
        hold("session failed");
    }

    (void)out_ign;
    sshe_net_close(&t.sock);
    pspDebugScreenPrintf("\nbye.\n");
    hold("done");
    return 0;
}