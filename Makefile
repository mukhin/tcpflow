CC = gcc
CFLAGS = -g -Wall

###

default: tcpflow

tcpflow: datalink.o main.o tcpip.o util.o
	$(CC) -o tcpflow datalink.o main.o tcpip.o util.o -lpcap

datalink.o: datalink.c tcpflow.h
	$(CC) $(CFLAGS) -c datalink.c

main.o: main.c tcpflow.h
	$(CC) $(CFLAGS) -c main.c

tcpip.o: tcpip.c tcpflow.h
	$(CC) $(CFLAGS) -c tcpip.c

util.o: util.c tcpflow.h
	$(CC) $(CFLAGS) -c util.c

