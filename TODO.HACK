For 0.8 or later:

    autoconf the entire build process for better portability
    Make nice little website in the Tor wml format and publish it on tpo:
        https://www.torproject.org/ttdnsd/
    Add bind configuration file that only forwards to ttdnsd
    Add RPM spec file for RPM builds

Certainly 0.9 but probably much later:

    re-write ttdnsd to use libevent
    re-write ttdnsd to no longer use tsocks
    Make supported DNS queries via Tor's SOCKS resolve method
    Should we filter all DNS replies and ensure that they do not contain
    private addresses. This is similar to the ClientDNSRejectInternalAddresses
    option that Tor has enabled by default.
