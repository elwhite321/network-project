objects:
	gcc -c protocol.c server.c client.c

server:
	gcc protocol.o server.o -o server.out

client:
	gcc protocol.o client.o -o client.out

all: objects client server