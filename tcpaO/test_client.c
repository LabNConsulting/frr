#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tcp_ao_config.h"
#include <errno.h>
#include "server_client_comm.h"


// Function to test setting TCP-AO
void test_set_tcpA0_sockopt_client() {
    printf("Starting test_set_tcpA0_sockopt\n");

    //Creating a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0){
		printf("Error creating the socket, errno: %d, %s\n", errno, strerror(errno));
		return;
	} else {
		printf("Socket created successfully\n");
	}

    // Setting the TCP-AO socket option on sock
    if(set_tcpA0_sockopt(sock, AF_INET, ALGORITHM, server_rcvid_client_sndid, client_rcvid_server_sndid, KEY) < 0){
        perror("Error setting the socket option: ");
        return;
    }


    //Creating a sockaddr_in struct to use when connecting to the server 
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);


    printf("Coneccting to the server...\n");
    
    //Connecting to the server
    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0){
        perror("Connect failed");
        return;
    }

    const char *message = "Hi";
    
    //Sending the message initialized above to the server
    printf("Sending message to the server\n");
    send(sock, message, strlen(message), 0);
    printf("Message sent to the server\n");

    close(sock);

    printf("test_set_tcpA0_sockopt passed.\n");
}

int main() {
    test_set_tcpA0_sockopt_client();
    return 0;
}
