TTDNSDVERSION= 0.7
GPGKEYID=E012B42D
EXEC = ttdnsd
CC = /usr/bin/gcc
CHROOT = /var/lib/ttdnsd
PIDFILE = $(CHROOT)/pid
CONF = ttdnsd.conf
TORTSOCKSCONF = tor-tsocks.conf
MANPAGE = ttdnsd.1
INITSCRIPT = ttdnsd.init
TSOCKSLIB = tsocks
# If the program ever grows, we'll enjoy this macro:
SRCFILES := $(wildcard *.c)
OBJFILES := $(patsubst %.c,%.o,$(wildcard *.c))
SUDO = sudo

# Build host specific additionals.  Uncomment whatever matches your situation.
# For BSD's with pkgsrc:
#EXTRA_CFLAGS = -I /usr/pkg/include -L /usr/pkg/lib

# Hardening and warnings for building with gcc
GCCWARNINGS = -Wall -fno-strict-aliasing -W -Wfloat-equal -Wundef	\
-Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes		\
-Wwrite-strings -Wredundant-decls -Wchar-subscripts -Wcomment		\
-Wformat=2 -Wwrite-strings -Wmissing-declarations -Wredundant-decls	\
-Wnested-externs -Wbad-function-cast -Wswitch-enum -Winit-self		\
-Wmissing-field-initializers -Wdeclaration-after-statement		\
-Wold-style-definition -Waddress -Wmissing-noreturn -Wnormalized=id	\
-Woverride-init -Wstrict-overflow=1 -Wextra -Warray-bounds		\
-Wstack-protector -Wformat -Wformat-security -Wpointer-sign
GCCHARDENING=-D_FORTIFY_SOURCE=2 -fstack-protector-all -fwrapv -fPIE --param ssp-buffer-size=1
LDHARDENING=-pie -z relro -z now

CFLAGS=-g -O2 $(EXTRA_CFLAGS) $(GCCHARDENING) $(GCCWARNINGS) -Werror
LDFLAGS= $(LDHARDENING)

all: $(SRCFILES)
	$(CC) $(CFLAGS) $(SRCFILES) -o $(EXEC) -l$(TSOCKSLIB) -L$(STAGING_DIR)/usr/lib

notsocks:	
	$(CC) $(CFLAGS) $(SRCFILES) -o $(EXEC) -L$(STAGING_DIR)/usr/lib

static: $(SRCFILES)
	$(CC) $(CFLAGS) -static $(SRCFILES) -o $(EXEC) -L$(STAGING_DIR)/usr/lib/libtsocks.a

clean:
	rm -f $(OBJFILES) $(EXEC)

install: all
#	strip $(EXEC)
	test -d $(DESTDIR)$(CHROOT) || mkdir -p $(DESTDIR)$(CHROOT)
	test -d $(DESTDIR)/etc/ || mkdir -p $(DESTDIR)/etc/
	cp $(CONF) $(DESTDIR)/etc/$(CONF)
	cp $(TORTSOCKSCONF) $(DESTDIR)$(CHROOT)/tsocks.conf
	test -d $(DESTDIR)/usr/sbin/ || mkdir -p $(DESTDIR)/usr/sbin/
	cp $(EXEC) $(DESTDIR)/usr/sbin/
	test -d $(DESTDIR)/usr/share/man/man1/ || mkdir -p $(DESTDIR)/usr/share/man/man1/
	cp $(MANPAGE) $(DESTDIR)/usr/share/man/man1/
	test -d $(DESTDIR)/etc/init.d/ || mkdir -p $(DESTDIR)/etc/init.d/
	cp $(INITSCRIPT) $(DESTDIR)/etc/init.d/ttdnsd
	test -d $(DESTDIR)/usr/share/doc/ttdnsd || mkdir -p \
    $(DESTDIR)/usr/share/doc/ttdnsd/
	cp -r sample-configurations $(DESTDIR)/usr/share/doc/ttdnsd/
	test -d $(DESTDIR)/etc/default/ || mkdir -p $(DESTDIR)/etc/default/
	cp ttdnsd.defaults $(DESTDIR)/etc/default/ttdnsd

uninstall: all
	rm $(DESTDIR)/usr/sbin/$(EXEC)
	rm $(DESTDIR)/etc/$(CONF)
	rm -ri $(DESTDIR)$(CHROOT)
	rm $(DESTDIR)/usr/share/man/man1/$(MANPAGE)
	rm $(DESTDIR)/etc/init.d/ttdnsd
	rm -r $(DESTDIR)/$(DESTDIR)/usr/share/doc/ttdnsd

demo: install
	echo "Killing ttdnsd"
	-killall -9 ttdnsd
	echo "Starting ttdnsd"
	echo "Starting ttdnsd"
	TSOCKS_CONF_FILE=tsocks.conf ttdnsd -b 127.0.0.1 -p 53 \
    -P $(PIDFILE) -l
	echo "Attempting to lookup MX record for torproject.org through ttdnsd"
	dig @127.0.0.1 -t mx torproject.org

basic-dns-test: all
	-$(SUDO) killall -9 ttdnsd
	$(SUDO) sh -ec 'TSOCKS_CONF_FILE=tsocks.conf ./ttdnsd -l'
	dig @127.0.0.1 -t mx torproject.org

deb-src:
	dpkg-buildpackage -S -rfakeroot -us -uc -I.git -i.git

deb:
	dpkg-buildpackage -rfakeroot -us -uc -I.git -i.git

deb-clean:
	-rm build
	debian/rules clean

src-tar-gz: clean
	cd .. && mv ttdnsd ttdnsd-$(TTDNSDVERSION) && \
    tar --owner=nobody --group=nogroup --exclude=.gitignore \
    --exclude=.git \
    -cvzf ttdnsd-$(TTDNSDVERSION).tar.gz ttdnsd-$(TTDNSDVERSION) && mv \
    ttdnsd-$(TTDNSDVERSION) ttdnsd

signed-src: src-tar-gz
	gpg -u $(GPGKEYID) --use-agent -ab ../ttdnsd-$(TTDNSDVERSION).tar.gz

git-tag:
	git tag -u $(GPGKEYID) ttdnsd-$(TTDNSDVERSION)
	git push origin ttdnsd-$(TTDNSDVERSION)

# These all work; you've broken something if these fail
demo-dns-tests: demo
	dig @127.0.0.1 -x 38.229.70.10
	dig @127.0.0.1 -t A torproject.org
	dig @127.0.0.1 -t SOA torproject.org
	dig @127.0.0.1 -t NS torproject.org
	dig @127.0.0.1 -t MX torproject.org
	dig @127.0.0.1 -t CNAME svn.freehaven.net
	dig @127.0.0.1 -t srv _xmpp-client._tcp.google.com
	dig @127.0.0.1 -t aaaa www.kame.net
	dig @127.0.0.1 -t RRSIG nic.se

stress-test:
	dig @127.0.0.1 -x 38.229.70.10
	dig @127.0.0.1 -t A torproject.org
	dig @127.0.0.1 -t SOA torproject.org
	dig @127.0.0.1 -t NS torproject.org
	dig @127.0.0.1 -t MX torproject.org
	dig @127.0.0.1 -t CNAME svn.freehaven.net
	dig @127.0.0.1 -t srv _xmpp-client._tcp.google.com
	dig @127.0.0.1 -t aaaa www.kame.net
	dig @127.0.0.1 -t RRSIG nic.se
