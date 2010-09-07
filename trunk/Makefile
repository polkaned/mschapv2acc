OS=$(shell uname -s)
ifeq ($(OS),Darwin)
	CC=gcc-4.0
else
	CC=gcc
endif

CFLAGS=-O2 -ggdb -Wall -msse2

all: mschapv2acc.o mschapv2lib.o md4.o des.o md4_sse2.o md4sse2.o wpe2acc.o
	$(CC) -o wpe2acc wpe2acc.o
	$(CC) -o mschapv2acc mschapv2acc.o mschapv2lib.o md4.o des.o md4_sse2.o md4sse2.o

wpe2acc.o: wpe2acc.c
	$(CC) -c wpe2acc.c $(CFLAGS)

mschapv2acc.o: mschapv2acc.c
	$(CC) -o mschapv2acc.o -c mschapv2acc.c $(CFLAGS)

mschapv2lib.o: mschapv2lib.c mschapv2lib.h
	$(CC) -o mschapv2lib.o -c mschapv2lib.c $(CFLAGS)

md4.o: md4.c md4.h
	$(CC) -o md4.o -c md4.c $(CFLAGS)

des.o: des.c des.h
	$(CC) -o des.o -c des.c $(CFLAGS)

md4_sse2.o : md4_sse2.S
	$(CC) -o md4_sse2.o -c md4_sse2.S $(CFLAGS)

md4sse2.o : md4sse2.c md4sse2.h
	$(CC) -o md4sse2.o -c md4sse2.c $(CFLAGS)

clean: 
	@-rm *.o mschapv2acc wpe2acc

