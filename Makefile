MAJOR_VERSION	= 0
MINOR_VERSION	= 0
PATCHLEVEL	= 1

VERSION		= $(MAJOR_VERSION).$(MINOR_VERSION).$(PATCHLEVEL)

CCPATH=/usr/bin/

CC	=$(CCPATH)gcc
CPP	=$(CCAPTH)g++
INSTALL	=$(CCPATH)install
MKDIR	=/bin/mkdir
CP      =/bin/cp

CFLAGS=-g -Wall -I.
CPPFLAGS=-g -Wall -fPIC -I. 

LIBS=
SF_OBJS=file-utils.o sfuzz.o os-abs.o
SNOOP_OBJS=snoop.o os-abs.o
PROGS=sfuzz

all: $(PROGS)

sfuzz: $(SF_OBJS)
	$(CC) -o $@ $(SF_OBJS) $(LIBS)

snoop: $(SNOOP_OBJS)
	$(CC) -o $@ $(SNOOP_OBJS) $(LIBS)

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $<

install: all
	$(INSTALL) sfuzz /usr/local/bin/sfuzz
	$(MKDIR) -p /usr/local/share/sfuzz-db
	$(CP) sfuzz-sample/* /usr/local/share/sfuzz-db
	echo Installed.

uninstall:
	$(RM) -rf /usr/local/share/sfuzz-db
	$(RM) -f  /usr/local/bin/sfuzz

clean:
	rm -f core *~ *.o $(PROGS) snoop