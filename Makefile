CC = gcc
CFLAGS = -g -Wall

###

default: tcpflow

tcpflow: datalink.o flow.o main.o tcpip.o util.o
	$(CC) -o tcpflow datalink.o flow.o main.o tcpip.o util.o -lpcap

datalink.o: datalink.c tcpflow.h
	$(CC) $(CFLAGS) -c datalink.c

flow.o: flow.c tcpflow.h
	$(CC) $(CFLAGS) -c flow.c

main.o: main.c tcpflow.h
	$(CC) $(CFLAGS) -c main.c

tcpip.o: tcpip.c tcpflow.h
	$(CC) $(CFLAGS) -c tcpip.c

util.o: util.c tcpflow.h
	$(CC) $(CFLAGS) -c util.c

