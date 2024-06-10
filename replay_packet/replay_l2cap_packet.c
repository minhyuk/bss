	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
	{
		perror("connect");
		exit(EXIT_FAILURE);
	}
	
	if( (sent=send(sock, replay_buggy_packet, SIZE, 0)) >= 0)
	{
		printf("L2CAP packet sent (%d)\n", sent);
	}

	printf("Buffer:\t");
	for(i=0; i<sent; i++)
		printf("%.2X ", (unsigned char) replay_buggy_packet[i]);
	printf("\n");

	close(sock);
	return EXIT_SUCCESS;
}
