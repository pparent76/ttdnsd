EXEC = ttdnsd
CC = /usr/bin/gcc
CHROOT = /var/run/ttdnsd/
CONF = ttdnsd.conf
TORTSOCKSCONF = tor-tsocks.conf
TSOCKSLIB = tsocks
# If the program ever grows, we'll enjoy this macro:
SRCFILES := $(wildcard *.c)
OBJFILES := $(patsubst %.c,%.o,$(wildcard *.c))

# Build host specific additionals.  Uncomment whatever matches your situation.
# For BSD's with pkgsrc:
#EXTRA_CFLAGS = -I /usr/pkg/include -L /usr/pkg/lib

# Hardening and warnings for building with gcc
CFLAGS=-O2 $(EXTRA_CFLAGS) -D_FORTIFY_SOURCE=2 -fstack-protector-all -fwrapv -fPIE -Wstack-protector -Wformat -Wformat-security -Wpointer-sign -Wall
LDFLAGS= -pie -z relro -z now

all: $(SRCFILES)
	$(CC) $(CFLAGS) $(SRCFILES) -o $(EXEC) -l$(TSOCKSLIB) -L$(STAGING_DIR)/usr/lib

notsocks:	
	$(CC) $(CFLAGS) $(SRCFILES) -o $(EXEC) -L$(STAGING_DIR)/usr/lib

static: $(SRCFILES)
	$(CC) $(CFLAGS) -static $(SRCFILES) -o $(EXEC) -L$(STAGING_DIR)/usr/lib/libtsocks.a

clean:
	rm -f $(OBJFILES) $(EXEC)

install: all
	strip $(EXEC)
	test -d $(DESTDIR)$(CHROOT) || -mkdir $(DESTDIR)$(CHROOT)
	cp $(CONF) $(DESTDIR)$(CHROOT)
	cp $(TORTSOCKSCONF) $(DESTDIR)$(CHROOT)/tsocks.conf
	cp $(EXEC) $(DESTDIR)/sbin/

uninstall: all
	rm $(DESTDIR)/sbin/$(EXEC)
	rm -ri $(DESTDIR)$(CHROOT)
