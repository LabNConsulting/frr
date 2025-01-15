#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <errno.h>
#include "tcp_ao_config.h"
#include "server_client_comm.h"


void test_set_tcpA0_sockopt_server(){
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);


    // Create a TCP socket for the server
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        return;
    }

    uint8_t sndid = 200, rcvid = 50;

    // Set the TCP-AO socket option on the server socket using the fucntion from 
    if (set_tcpA0_sockopt(server_sock, AF_INET, ALGORITHM, client_rcvid_server_sndid, server_rcvid_client_sndid, KEY) < 0) {
        close(server_sock);
        return;
    }

    //Setting up the server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    //Binding the socket to the address
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        return;
    }

    //Listening on the server socket
    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        close(server_sock);
        return;
    }

    printf("Server listening on port %d\n", PORT);

    //Accepting incoming connections
    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        } else {
            // Read the message from the connection accepted
            char buffer[1024] = {0};
            int bytes_read = read(client_sock, buffer, sizeof(buffer));
            if (bytes_read > 0) {
                printf("Received message: %s\n", buffer);
            }
            close(client_sock);
        }
        
    }

    close(server_sock);
}

int main() {
    test_set_tcpA0_sockopt_server();
    return 0;

}
