//TCP-AO Configuration Current status: Working
//All we are really doing here is adding a new MKT to the socket
#define _GNU_SOURCE
#include <linux/tcp.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#define LISTEN_BACKLOG 50
//Connect, listen, bind, and accept are all set based on the value given (true or false)
int set_tcpA0_sockopt(int sock, int family, const char *alg_name, uint8_t sndid, const char *key, uint8_t rcvid)
{
		
	//Setting up the MKT
	struct sockaddr_in addr = {
		.sin_family = family, 
	};


    int keylen = key ? strlen(key) : 0;

	if (keylen > TCP_AO_MAXKEYLEN){
		printf("Key length is too long\n");
		return -1;
	}


	struct tcp_ao_add tcp_ao = {};

	//Setting the socket 
	
	tcp_ao.sndid = sndid;
	
	tcp_ao.rcvid = rcvid;
	
	tcp_ao.keylen = keylen;

	memcpy(tcp_ao.key, key, sizeof(key));

	strcpy(tcp_ao.alg_name, alg_name);

	memcpy(&tcp_ao.addr, &addr, sizeof(addr));


	printf("Setting the socket option\n");
	int ret = setsockopt(sock, IPPROTO_TCP, TCP_AO_ADD_KEY, &tcp_ao, sizeof(tcp_ao));
	if (ret < 0){
		printf("Error setting the socket option, errno: %d, %s\n", errno, strerror(errno));
		return -1;
	} else {
		printf("Socket option set successfully\n");
	}
	return ret;
}




