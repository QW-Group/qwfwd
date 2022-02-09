EXTRACFLAGS=-Wall -O2
ifeq ($(MAKECMDGOALS),qwfwd-dl)
	EXTRACFLAGS += -fPIC -pthread -D APP_DLL
endif
ifeq ($(MAKECMDGOALS),qwfwd-dl32)
	EXTRACFLAGS += -m32 -fPIC -pthread -D APP_DLL
endif

CC=gcc $(EXTRACFLAGS)

OBJS = src/ban.o src/clc.o src/cmd.o src/info.o src/main.o src/msg.o src/net.o src/peer.o src/svc.o src/sys.o src/query.o src/cvar.o src/fs.o src/token.o src/huff.o

qwfwd: $(OBJS) src/qwfwd.h
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@.bin -lm

qwfwd.exe: *.c *.h
	$(MAKE) qwfwd CFLAGS=-mno-cygwin LDFLAGS="-lwsock32 -lwinmm"
	mv qwfwd qwfwd.exe

qwfwd-dl: $(OBJS) qwfwd.h
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -shared -Wl -o qwfwd.so -lm

qwfwd-dl32: $(OBJS) qwfwd.h
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -shared -Wl -o qwfwd.so -lm

clean:
	rm -rf qwfwd.bin qwfwd.exe qwfwd.db *.o qwfwd.so qwfwd-db.so

