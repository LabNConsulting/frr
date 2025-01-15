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


/*
This function sets the socket option for the TCP-AO
*/
int set_tcpA0_sockopt(int sock, int family, const char *alg_name, uint8_t sndid, uint8_t rcvid,  const char *key)
{

	struct sockaddr_in addr = {
		.sin_family = family, 
	};

    int keylen = key ? strlen(key) : 0;

	if (keylen > TCP_AO_MAXKEYLEN){
		perror("Key length is too long");
		return -1;
	}


	//Setting up the struct for the TCP-AO key addition
	struct tcp_ao_add tcp_ao = {};
	
	tcp_ao.sndid = sndid;
	
	tcp_ao.rcvid = rcvid;
	
	tcp_ao.keylen = keylen;

	memcpy(tcp_ao.key, key, sizeof(key));

	strcpy(tcp_ao.alg_name, alg_name);

	memcpy(&tcp_ao.addr, &addr, sizeof(addr));

	//Setting the socket option
	int ret = setsockopt(sock, IPPROTO_TCP, TCP_AO_ADD_KEY, &tcp_ao, sizeof(tcp_ao));

	if (ret < 0)
		perror("Error setting the socket option: ");
	
	return ret;
}




