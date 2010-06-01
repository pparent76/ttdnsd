EXEC = ttdnsd

all: main.c
	$(CC) $(CFLAGS) main.c -o $(EXEC) -ltsocks -L$(STAGING_DIR)/usr/lib

notsocks:	
	$(CC) $(CFLAGS) main.c -o $(EXEC) -L$(STAGING_DIR)/usr/lib

static: main.c
	$(CC) $(CFLAGS) main.c -o $(EXEC) $(STAGING_DIR)/usr/lib/libtsocks.a

clean:
	rm -f main.o $(EXEC)

install: all
	cp $(EXEC) $(DESTDIR)
	cp ttdnsd.conf $(DESTDIR)
