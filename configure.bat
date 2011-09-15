@ECHO OFF
REM I cannot believe that after ... 20 years of not writing any MS-DOS batch
REM files I remembered as much as I did.

REM also, only need to check for --disable-plugins and --enable-snoop since I
REM cannot seem to get awesomeness of ssl under windows - someone might have a
REM fix.

echo # This file was automatically built by the simple fuzzer configuration process > Makefile
echo # Manual edits will not be saved if you run configure again >> Makefile
echo # you have been warned. >> Makefile
echo ### Variables for building >> Makefile
echo CCPATH=C:\MinGW\bin>> Makefile
echo CC=gcc >> Makefile
echo INSTALL=copy>> Makefile
echo TARGET_PLAT=win>> Makefile
echo CP=copy>> Makefile
echo CAT=type>> Makefile
echo UNAME=uname>> Makefile
echo LS=dir>> Makefile
echo PREFIX=C:\sfuzz>> Makefile
echo RM=del>> Makefile
echo MKDIR=md>> Makefile
echo ###>> Makefile
echo CFLAGS=-g -O2 -I. -Wall -Werror -D_GNU_SOURCE -D__WIN32__ -DPREFIX="$(PREFIX)" -DWINVER=0x0501>> Makefile
echo SHARED_INC=file-utils.o os-abs.o>> Makefile
echo SHARED_OPTS=-shared -lws2_32>> Makefile
echo LIBS=-lws2_32>> Makefile
echo ###>> Makefile
echo SF_OBJS=file-utils.o sfuzz.o os-abs.o sfo_interface.o>> Makefile
echo SNOOP_OBJS=snoop.o os-abs.o >> Makefile
echo PLUGIN_EXAMPLE_OBJS=sfuzz-plugin-example.o sfuzz-plugin-ssl-transport.o sfuzz-server-plugin.o>> Makefile
echo ###>> Makefile
echo BIN_DIR=$(PREFIX)\bin\>> Makefile
echo SHARE_DIR=$(PREFIX)\share\>> Makefile
echo SFUZZ_SAMPLE=sfuzz-sample\>> Makefile
echo ###>> Makefile
echo ### Hack for DOS echo - can't make a newline easily.
echo all: sfuzz.exe sfuzz-plugin-example.so sfuzz-server-plugin.so >> Makefile
echo ###>> Makefile
type Makefile.in >> Makefile

echo Configured for windows - edit the Makefile to point to the correct paths.