EXEC = ttdnsd
CC = /usr/bin/gcc
CHROOT = /var/run/ttdnsd/
CONF = ttdnsd.conf

# Hardening and warnings for building with gcc
CFLAGS=-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-all -fwrapv -fPIE -Wstack-protector -Wformat -Wformat-security -Wpointer-sign -Wall
LDFLAGS= -pie -z relro -z now

all: main.c
	$(CC) $(CFLAGS) main.c -o $(EXEC) -ltsocks -L$(STAGING_DIR)/usr/lib

notsocks:	
	$(CC) $(CFLAGS) main.c -o $(EXEC) -L$(STAGING_DIR)/usr/lib

static: main.c
	$(CC) $(CFLAGS) main.c -o $(EXEC) $(STAGING_DIR)/usr/lib/libtsocks.a

clean:
	rm -f main.o $(EXEC)

install: all
	mkdir $(CHROOT)
	cp $(CONF) $(CHROOT)
	cp $(EXEC) $(DESTDIR)/usr/sbin/
	cp ttdnsd.conf $(DESTDIR)/etc/
