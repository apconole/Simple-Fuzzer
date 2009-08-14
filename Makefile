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

CFLAGS=-g -Wall -I. -fPIC
CPPFLAGS=-g -Wall -fPIC -I. 

LIBS= 
SF_OBJS=file-utils.o sfuzz.o os-abs.o
SNOOP_OBJS=snoop.o os-abs.o
EXAMPLE_OBJS=sfuzz-plugin-example.o sfuzz-plugin-ssl-transport.o
PROGS=sfuzz sfuzz-plugin-example.so sfuzz-plugin-ssl-transport.so

ifeq ($(TARGET_PLAT),)
TARGET_PLAT = $(shell uname -s)
endif

ifeq ($(TARGET_PLAT),Linux)
LDFLAGS = -rdynamic
CFLAGS += -D__LINUX__ -rdynamic
SHARED_OPTS = -shared -rdynamic
LIBS += -ldl
endif

ifeq ($(TARGET_PLAT),Darwin)
LDFLAGS =
CFLAGS += -D__LINUX__
SHARED_OPTS = -dynamiclib -undefined dynamic_lookup -single_module
LIBS += -ldl
endif

ifeq ($(TARGET_PLAT),win)
CCPATH=
LDFLAGS=
LIBS += -lws2_32
CFLAGS += -D__WIN32__
SHARED_OPTS = -shared
endif

all: $(PROGS)

sfuzz: $(SF_OBJS)
	$(CC) -o $@ $(SF_OBJS) $(LDFLAGS) $(LIBS)

%.so: %.o
	$(CC)  $(SHARED_OPTS) -o $@ $<

snoop: $(SNOOP_OBJS)
	$(CC) -o $@ $(SNOOP_OBJS) $(LIBS)

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $<

install: all
	$(INSTALL) sfuzz /usr/local/bin/sfuzz
	$(MKDIR) -p /usr/local/share/sfuzz-db
	$(CP) sfuzz-sample/* /usr/local/share/sfuzz-db
	$(CP) *.so /usr/local/share/sfuzz-db
	echo Installed.

uninstall:
	$(RM) -rf /usr/local/share/sfuzz-db
	$(RM) -f  /usr/local/bin/sfuzz

clean:
	rm -f core *~ *.o $(PROGS) snoop