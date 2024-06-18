// Client side C program to demonstrate Socket
// programming
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "tinypsk.h"
#include "tp_vault.h"

#define PORT 8050

int socket_send(void *s, const void *buf, size_t size) {
	
    print_debug("Sending these bytes:\n");
    print_debug_arr(buf, size);

    return (int)send((int)s, buf, size, 0);
}

int socket_recv(void *s, void *buf, size_t size) {

    int res = (int)recv((int)s, buf, size, 0);
    if (res >= 0) {
        print_debug("Receiving these bytes:\n");
        print_debug_arr(buf, res);
    }
    else
        print_debug("Error in socket recv\n");

    return res;
}

int main(int argc, char const* argv[])
{
	int status, client_fd;
	struct sockaddr_in serv_addr;

	unsigned char rcv_buff[1024];
    char str[] = "Hello World, This is the default simulation!\n"
                 "This is an echo!\nThis is an echo...\n";
	
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	// Convert IPv4 and IPv6 addresses from text to binary
	// form
	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)
		<= 0) {
		printf(
			"\nInvalid address/ Address not supported \n");
		return -1;
	}
	if ((status
		= connect(client_fd, (struct sockaddr*)&serv_addr,
				sizeof(serv_addr)))
		< 0) {
		printf("\nConnection Failed \n");
		return -1;
	}

    uint16_t psk_id = 11;
    tp_sock_t tls_sock;

    tp_cred_t creds[] = {
        TP_CRED(11, "THIS IS THE PRE-SHARED KEY."),
        TP_CRED(22, "THIS IS THE PRE-SHARED KEY.")
    };
    tp_vault_set(creds, 2);

    if (tp_initC(&tls_sock, psk_id, (void *)client_fd, socket_send, socket_recv,
        tp_vault_get_ms) < 0) {
        perror("tls init error");
        exit(EXIT_FAILURE);
    }

    int res = tp_handshake(&tls_sock);
    if (res < 0) {
        fprintf(stderr, "Error %d on handshake\n", res);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Printing our Server_Client random\n");
    for (size_t i = 0; i < 64; i++)
        fprintf(stderr, "%x ", ((uint8_t *)&tls_sock.h.S_C_randoms)[i]);
    fprintf(stderr, "\n");

    fprintf(stderr, "Printing our master secret\n");
    for (size_t i = 0; i < 48; i++)
        fprintf(stderr, "%x ", tls_sock.h.master_secret[i]);
    fprintf(stderr, "\n");

    fprintf(stderr, "Printing our Client Write key\n");
    for (size_t i = 0; i < 32; i++)
        fprintf(stderr, "%x ", tls_sock.C_S_write_MAC_key[0][i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "Printing our Server Write key\n");
    for (size_t i = 0; i < 32; i++)
        fprintf(stderr, "%x ", tls_sock.C_S_write_MAC_key[1][i]);
    fprintf(stderr, "\n");


	tp_send(&tls_sock, str, sizeof(str));
    int rcvd = tp_recv(&tls_sock, rcv_buff, sizeof(rcv_buff));
    if (rcvd > 0)
        fprintf(stderr, "%s", rcv_buff);

	// closing the connected socket
    close(client_fd);
	return 0;
}
