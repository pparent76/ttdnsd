EXEC = ttdnsd
CC = /usr/bin/gcc
CHROOT = /var/run/ttdnsd/
CONF = ttdnsd.conf
TORTSOCKSCONF = tor-tsocks.conf
TSOCKSLIB = tsocks
OPENSSLLIB = ssl
# If the program ever grows, we'll enjoy this macro:
SRCFILES := $(wildcard *.c)
OBJFILES := $(patsubst %.c,%.o,$(wildcard *.c))

# Build host specific additionals.  Uncomment whatever matches your situation.
# For BSD's with pkgsrc:
#EXTRA_CFLAGS = -I /usr/pkg/include -L /usr/pkg/lib

# Hardening and warnings for building with gcc
GCCWARNINGS = -Wall -fno-strict-aliasing -W -Wfloat-equal -Wundef -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes -Wwrite-strings -Wredundant-decls -Wchar-subscripts -Wcomment -Wformat=2 -Wwrite-strings -Wmissing-declarations -Wredundant-decls -Wnested-externs -Wbad-function-cast -Wswitch-enum -Winit-self -Wmissing-field-initializers -Wdeclaration-after-statement -Wold-style-definition -Waddress -Wmissing-noreturn -Wnormalized=id -Woverride-init -Wstrict-overflow=1 -Wextra -Warray-bounds -Wstack-protector -Wformat -Wformat-security -Wpointer-sign
GCCHARDENING=-D_FORTIFY_SOURCE=2 -fstack-protector-all -fwrapv -fPIE --param ssp-buffer-size=1
LDHARDENING=-pie -z relro -z now

CFLAGS=-g -O2 $(EXTRA_CFLAGS) $(GCCHARDENING) $(GCCWARNINGS) -Werror
LDFLAGS= $(LDHARDENING)

all: $(SRCFILES)
	$(CC) $(CFLAGS) $(SRCFILES) -o $(EXEC) -l$(TSOCKSLIB) -l$(OPENSSLLIB) -L$(STAGING_DIR)/usr/lib

notsocks:	
	$(CC) $(CFLAGS) $(SRCFILES) -o $(EXEC) -L$(STAGING_DIR)/usr/lib

static: $(SRCFILES)
	$(CC) $(CFLAGS) -static $(SRCFILES) -o $(EXEC) -L$(STAGING_DIR)/usr/lib/libtsocks.a

clean:
	rm -f $(OBJFILES) $(EXEC)

install: all
	strip $(EXEC)
	test -d $(DESTDIR)$(CHROOT) || mkdir -p $(DESTDIR)$(CHROOT)
	cp $(CONF) $(DESTDIR)$(CHROOT)
	cp $(TORTSOCKSCONF) $(DESTDIR)$(CHROOT)/tsocks.conf
	cp $(EXEC) $(DESTDIR)/sbin/

uninstall: all
	rm $(DESTDIR)/sbin/$(EXEC)
	rm -ri $(DESTDIR)$(CHROOT)

demo: all
	echo "Starting ttdnsd"
	TSOCKS_CONF_FILE=tsocks.conf ttdnsd -b 127.0.0.1 -p 53 \
    -P /var/run/ttdnsd/pid
	echo "Attempting to lookup MX record for torproject.org through ttdnsd"
	dig @127.0.0.1 -t mx torproject.org

