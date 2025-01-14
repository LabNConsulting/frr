.PHONY: all clean kill

PORT := $(shell grep '#define PORT' server_client_comm.h | awk '{print $$3}')

all:	test_server	test_client

test_server: test_server.c	tcp_ao_config.c
	gcc	-o	test_server	test_server.c	tcp_ao_config.c

test_client: test_client.c tcp_ao_config.c
	gcc -o test_client test_client.c tcp_ao_config.c

kill:
	sudo kill -9 $$(sudo lsof -t -i:$(PORT))

clean:
	rm -f test_server test_client