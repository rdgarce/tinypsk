#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "tinypsk.h"
#include "tp_vault.h"

int socket_send(void *s, const void *buf, size_t size) {

    return (int)send((int)s, buf, size, 0);
}

int socket_recv(void *s, void *buf, size_t size) {

    return (int)recv((int)s, buf, size, 0);
}

// Server side C program to demonstrate Socket
// programming
#define PORT 5555

int main(int argc, char const* argv[])
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
 
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
 
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr*)&address,
             sizeof(address))
        < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket
         = accept(server_fd, (struct sockaddr*)&address,
                  &addrlen))
        < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }


    tp_cred_t creds[] = {
        TP_CRED(11, "psk11"),
        TP_CRED(22, "psk22")
    };
    tp_vault_set(creds, 2);

    tp_sock_t tls_sock;
    if (tp_initS(&tls_sock, (void *)new_socket, socket_send, socket_recv, tp_vault_get_ms) < 0) {
        perror("tls init error");
        exit(EXIT_FAILURE);
    }

    int res = tp_handshake(&tls_sock);
    if (res < 0) {
        fprintf(stderr, "Error %d on handshake\n", res);
        exit(EXIT_FAILURE);
    }
    
    unsigned char rcv_buff[1024];

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


    int recvd = tp_recv(&tls_sock, rcv_buff, sizeof(rcv_buff));
    fprintf(stderr, "%s", rcv_buff);
    tp_send(&tls_sock, rcv_buff, recvd);

    // closing the connected socket
    close(new_socket);
    // closing the listening socket
    close(server_fd);
    return 0;
}