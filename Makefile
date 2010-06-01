EXEC = ttdnsd

all: main.c resolv
	$(CC) $(CFLAGS) main.c -o $(EXEC) -ltsocks -L$(STAGING_DIR)/usr/lib

resolv:
	cd ttdnstor; make; cp *.so.1 ..

resolvclean:
	rm -f *.so.1
	cd ttdnstor; make clean

static: main.c
	$(CC) $(CFLAGS) main.c -o $(EXEC) $(STAGING_DIR)/usr/lib/libtsocks.a

clean: resolvclean
	rm -f main.o $(EXEC)

install: all
	cp $(EXEC) $(DESTDIR)
	cp ttdnsd.conf $(DESTDIR)
