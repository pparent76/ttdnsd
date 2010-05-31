/*
 *
 *  Usage: 
 *   export TTDNSD_REALRESOLVCONF=PATH_TO_NON_TTDNSD_RESOLV_CONF
 *   LD_PRELOAD=PATH_TO/libttdnsd.so.1 APP_TO_USE_DNS_WITHOUT_TTDNSD
 *
 *  License: GPLv2
 */

#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <string.h>

#define ENV_RESOLV "TTDNSD_REALRESOLVCONF"
#define RESOLVCONF "/etc/resolv.conf"
#define LIBC "libc.so.6"

int (*realopen)(const char *pathname, int flags) = NULL;
void* (*realfopen)(const char *pathname, char *mode) = NULL;

int open(const char *pathname, int flags)
{
	char *openpath = (char*) pathname;
	char *resolvconf = NULL;
	void *lib;
	
	if (!realopen) {
		lib = dlopen(LIBC, RTLD_LAZY);
		realopen = dlsym(lib, "open");
		dlclose(lib);
	}
	
	if (strcmp(pathname, RESOLVCONF) == 0) {
		resolvconf = getenv(ENV_RESOLV);

		openpath = (char*) ((resolvconf) ? resolvconf : pathname);
	}
	
	return realopen(openpath, flags);
}

void* fopen(const char *pathname, char *mode)
{
	char *openpath = (char*) pathname;
	char *resolvconf = NULL;
	void *lib;

	if (!realfopen) {
		lib = dlopen(LIBC, RTLD_LAZY);
		realfopen = dlsym(lib, "fopen");
		dlclose(lib);
	}
	
	if (strcmp(pathname, RESOLVCONF) == 0) {
		resolvconf = getenv(ENV_RESOLV);

		openpath = (char*) ((resolvconf) ? resolvconf : pathname);
	}
	
	return realfopen(openpath, mode);
}

