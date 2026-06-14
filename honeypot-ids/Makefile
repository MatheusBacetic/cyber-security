CC = gcc
CFLAGS = -Wall -Wextra -Iinclude

SRC = src/main.c src/server.c src/logger.c src/ids.c src/nftables.c

OUT = honeypot

all: 
	$(CC) $(CFLAGS) $(SRC) -o $(OUT)

clean: 
	rm -f $(OUT)
