#include <stdint.h>

int set_tcpA0_sockopt(int sock, int family, const char *alg_name, uint8_t sndid, uint8_t rcvid, const char *key);
