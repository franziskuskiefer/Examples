# TLS SRP Server - Client Test
CC=gcc
OPENSSL=/home/franziskus/Surrey/workspace/openssl-1.0.1c
CGLAGS=-I $(OPENSSL)/include/
LDFLAGS=-L $(OPENSSL) -lssl -lcrypto -ldl

COUTPUT=client
CSRC=client.c

SOUTPUT=server
SSRC=server.c

OUTPUT=$(COUTPUT) $(SOUTPUT)

all: server client
	echo "Finished make client and server"
	
server:
	$(CC) $(CFLAGS) $(SSRC) $(LDFLAGS) -o $(SOUTPUT)
	
client:
	$(CC) $(CFLAGS) $(CSRC) $(LDFLAGS) -o $(COUTPUT)
	
clean:
	rm -rf $(OUTPUT)