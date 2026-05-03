CC = gcc
CFLAGS = -Wall -Wextra -O2

all: server client c_scp

server: server.c
	$(CC) $(CFLAGS) -o server server.c

client: client.c
	$(CC) $(CFLAGS) -o client client.c

c_scp: c_scp.c
	$(CC) $(CFLAGS) -o c_scp c_scp.c

clean:
	rm -f server client c_scp
