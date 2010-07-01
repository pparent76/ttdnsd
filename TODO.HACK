For 0.5 or later:

    Add service like funcionality for Ubuntu and other flavors of Gnu/Linux
    Ask helix to package for deb.torproject.org.
    autoconf the entire build process for better portability
    make it simple to bump the version number for ttdnsd during release time
        currently, a release requires editing many files:
        Makefile, debian/control, debian/changelog, ttdnsd.h, package/ttdnsd/Makefile
    Make nice little website in the Tor wml format and publish it

Certainly 0.5 but probably much later:

    re-write ttdnsd to use libevent
    Make supported DNS queries via Tor's SOCKS resolve method

