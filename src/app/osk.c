/*
 * osk.c — single-line on-screen keyboard input for the PSP.
 *
 * Wraps sceUtilityOsk: one text field, ASCII in/out (the SSH fields
 * are all ASCII: host/IP/port/user/pass/commands). Returns the
 * entered string or NULL if cancelled.
 *
 * Modeled on the official PSPSDK osk sample (utility/osk/main.c).
 */

#include <pspkernel.h>
#include <pspdisplay.h>
#include <psputility.h>
#include <psputility_osk.h>
#include <psputility_sysparam.h>
#include <string.h>

#include "osk.h"

#define TEXT_LENGTH 128
#define MAX_CHARS   126

/* wide-char buffer helpers: ASCII <-> 16-bit */
static void ascii_to_wide(unsigned short *w, const char *s)
{
    int i;
    for (i = 0; i < TEXT_LENGTH - 1 && s[i]; i++)
        w[i] = (unsigned short)(unsigned char)s[i];
    w[i] = 0;
}

static int wide_to_ascii(char *s, int slen, const unsigned short *w)
{
    int i;
    for (i = 0; i < slen - 1 && w[i]; i++)
        s[i] = (char)(w[i] & 0x7F);
    s[i] = 0;
    return i;
}

/* Run the OSK; returns 1 if text was entered (out filled), 0 on
 * cancel. The utility renders its own overlay; caller supplies the
 * field description and pre-fill text. */
int osk_input(const char *desc, const char *initial, char *out, int outlen)
{
    unsigned short wdesc[TEXT_LENGTH];
    unsigned short winit[TEXT_LENGTH];
    unsigned short wout[TEXT_LENGTH];
    SceUtilityOskData data;
    SceUtilityOskParams params;
    int done = 0;
    int status;

    memset(wdesc, 0, sizeof(wdesc));
    memset(winit, 0, sizeof(winit));
    memset(wout, 0, sizeof(wout));
    ascii_to_wide(wdesc, desc);
    if (initial) ascii_to_wide(winit, initial);

    memset(&data, 0, sizeof(data));
    data.language = PSP_UTILITY_OSK_LANGUAGE_DEFAULT;
    data.lines = 1;
    data.unk_24 = 1;
    data.inputtype = PSP_UTILITY_OSK_INPUTTYPE_ALL;
    data.desc = wdesc;
    data.intext = winit;
    data.outtextlength = TEXT_LENGTH;
    data.outtextlimit = MAX_CHARS;
    data.outtext = wout;

    memset(&params, 0, sizeof(params));
    params.base.size = sizeof(params);
    sceUtilityGetSystemParamInt(PSP_SYSTEMPARAM_ID_INT_LANGUAGE,
                                &params.base.language);
    sceUtilityGetSystemParamInt(PSP_SYSTEMPARAM_ID_INT_BUTTON_SWAP,
                                &params.base.buttonSwap);
    params.base.graphicsThread = 17;
    params.base.accessThread = 19;
    params.base.fontThread = 18;
    params.base.soundThread = 16;
    params.datacount = 1;
    params.data = &data;

    if (sceUtilityOskInitStart(&params) < 0)
        return 0;

    while (!done) {
        sceDisplayWaitVblankStart();
        status = sceUtilityOskGetStatus();
        switch (status) {
        case PSP_UTILITY_DIALOG_INIT:
            break;
        case PSP_UTILITY_DIALOG_VISIBLE:
            sceUtilityOskUpdate(1);
            break;
        case PSP_UTILITY_DIALOG_QUIT:
            sceUtilityOskShutdownStart();
            break;
        case PSP_UTILITY_DIALOG_FINISHED:
            break;
        case PSP_UTILITY_DIALOG_NONE:
        default:
            done = 1;
            break;
        }
        sceDisplayWaitVblankStart();
    }

    if (data.result == PSP_UTILITY_OSK_RESULT_CHANGED) {
        wide_to_ascii(out, outlen, wout);
        return 1;
    }
    return 0;
}