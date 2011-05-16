EXTRACFLAGS=-Wall -O2
ifeq ($(MAKECMDGOALS),qwfwd-dl)
	EXTRACFLAGS += -fPIC -pthread -D APP_DLL
endif
ifeq ($(MAKECMDGOALS),qwfwd-dl32)
	EXTRACFLAGS += -m32 -fPIC -pthread -D APP_DLL
endif

CC=gcc $(EXTRACFLAGS)

OBJS = ban.o clc.o cmd.o info.o main.o msg.o net.o peer.o svc.o sys.o query.o cvar.o fs.o token.o huff.o

qwfwd: $(OBJS) qwfwd.h
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

