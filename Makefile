CC = gcc
CFLAGS = -Wall -Wextra -O2
OS := $(shell uname)

LDFLAGS = -lssl -lcrypto
ifeq ($(OS),Linux)
	LDFLAGS += -lutil
endif
ifeq ($(OS),Darwin)
	CFLAGS += -I/opt/homebrew/opt/openssl/include -I/usr/local/opt/openssl/include
	LDFLAGS += -L/opt/homebrew/opt/openssl/lib -L/usr/local/opt/openssl/lib
endif

all: cert server client c_scp

cert: server.key server.crt

server.key server.crt:
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt -subj "/CN=localhost" 2>/dev/null || true

server: server.c
	$(CC) $(CFLAGS) -o server server.c $(LDFLAGS)

client: client.c
	$(CC) $(CFLAGS) -o client client.c $(LDFLAGS)

c_scp: c_scp.c
	$(CC) $(CFLAGS) -o c_scp c_scp.c $(LDFLAGS)

clean:
	rm -f server client c_scp server.key server.crt
