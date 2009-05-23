CC = gcc
LIBS = -lpcap
CFLAGS = -Wall -g

.PHONY: all
all: lenovoclient

lenovoclient	: md5.o lenovoclient.o
	$(CC) $(CFLAGS) -o $@ md5.o lenovoclient.o $(LIBS)

md5.o	: md5.c md5.h
	$(CC) $(CFLAGS) -c $<

lenovoclient.o : lenovoclient.c
	$(CC) $(CFLAGS) -c $<
	
clean :
	rm -v *.o
