MAJOR_VERSION	= 0
MINOR_VERSION	= 0
PATCHLEVEL	= 1

VERSION		= $(MAJOR_VERSION).$(MINOR_VERSION).$(PATCHLEVEL)

CC=gcc
CPP=g++
INSTALL		= install

CFLAGS=-g -Wall -I.
CPPFLAGS=-g -Wall -fPIC -I. 

LIBS=
SF_OBJS=file-utils.o sfuzz.o os-abs.o
PROGS=sfuzz

all: $(PROGS)

sfuzz: $(SF_OBJS)
	$(CC) -o $@ $(SF_OBJS)

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $<

clean:
	rm -f core *~ *.o $(PROGS)