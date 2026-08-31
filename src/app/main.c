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

static int init_net(void)
{
    if (sceNetInit(0x80000, 42, 0, 42, 0) != 0) return -1;
    if (sceNetInetInit() != 0) return -1;
    if (sceNetApctlInit(0x8000, 48) != 0) return -1;
    return 0;
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
        pspDebugScreenPrintf("no config at %s\n", CONFIG);
        return 1;
    }

    if (init_net() != 0) {
        pspDebugScreenPrintf("net init failed\n");
        return 1;
    }

    memset(&t, 0, sizeof(t));
    if (sshe_net_connect(&t.sock, cfg_host, cfg_port) != 0) {
        pspDebugScreenPrintf("connect failed\n");
        return 1;
    }

    if (sshe_tx_handshake(&t, "SSH-2.0-PSPSSH_0.1") != 0) {
        pspDebugScreenPrintf("handshake failed\n");
        sshe_net_close(&t.sock);
        return 1;
    }
    pspDebugScreenPrintf("connected: %s\n", t.server_id);
    pspDebugScreenPrintf("host key: %02x%02x%02x%02x...\n",
                         t.server_pk[0], t.server_pk[1],
                         t.server_pk[2], t.server_pk[3]);

    if (sshe_client_run(&t, cfg_user, cfg_pass,
                        cfg_cmd[0] ? cfg_cmd : NULL,
                        out_print, NULL, NULL, NULL) != 0) {
        pspDebugScreenPrintf("session failed\n");
    }

    (void)out_ign;
    sshe_net_close(&t.sock);
    pspDebugScreenPrintf("\nbye.\n");
    return 0;
}