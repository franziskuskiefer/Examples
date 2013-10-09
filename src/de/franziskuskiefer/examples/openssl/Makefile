# TLS SRP Server - Client Test
CC=gcc
CFLAGS=
LDFLAGS=-lssl -lcrypto 

COUTPUT=client
CSRC=client.c

SOUTPUT=server
SSRC=server.c

OUTPUT=$(COUTPUT) $(SOUTPUT)

all: server client
	echo "Finished make client and server"
	
server:
	$(CC) $(CFLAGS) $(SSRC) $(LDFLAGS) -o $(SOUTPUT)
	
client: cleanClient
	$(CC) $(CFLAGS) $(CSRC) $(LDFLAGS) -o $(COUTPUT)
	
clean:
	rm -rf $(OUTPUT)
	
cleanClient:
	rm -rf $(COUTPUT)

