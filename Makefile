objects = base64.o omfuncs.o
#DEBUG=-g
CFLAGS=$(DEBUG)

all: omcmd

omcmd: $(objects) omcmd.c omcmd.h
	$(CC) $(CFLAGS) -o omcmd omcmd.c $(objects) ../dhcpctl/libdhcpctl.a ../common/libdhcp.a ../omapip/libomapi.a ../bind/lib/libdns.a ../bind/lib/libisc.a

omfuncs.o: omfuncs.c

clean:
	rm -f omcmd *.o
