/*
 *  The Tor TCP DNS Daemon
 *
 *  Copyright (c) Collin R. Mulliner <collin(AT)mulliner.org>
 *  Copyright (c) 2010, The Tor Project, Inc.
 *
 *  http://www.mulliner.org/collin/ttdnsd.php
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <limits.h>
#include "ttdnsd.h"

/*
 *  binary is linked with libtsocks therefore all TCP connections will
 *  be routed over Tor (if tsocks.conf is setup to chain with Tor)
 *
 *  see makefile about disableing tsocks (for testing)
 *
 */

static unsigned long int *nameservers; /**< nameservers pool */
static unsigned int num_nameservers; /**< number of nameservers */

static struct peer_t peers[MAX_PEERS]; /**< TCP peers */
static struct request_t requests[MAX_REQUESTS]; /**< request queue */
static int udp_fd; /**< port 53 socket */

/*
Someday:
static int multipeer = 0;
static int multireq = 0;
*/

/* Return a positive positional number or -1 for unfound entries. */
int request_find(int id)
{
    int pos = id % MAX_REQUESTS;

    for (;;) {
        if (requests[pos].id == id) {
            printf("found id=%d at pos=%d\n", id, pos);
            return pos;
        }
        else {
            pos++;
            pos %= MAX_REQUESTS;
            if (pos == (id % MAX_REQUESTS)) {
                printf("can't find id=%d\n", id);
                return -1;
            }
        }
    }
}


/* Returns 1 upon non-blocking connection setup; 0 upon serious error */
int peer_connect(uint peer, int ns)
{
    struct peer_t *p;
    int socket_opt_val = 1;
    int cs;

    if (peer > MAX_PEERS) // Perhaps we should just assert() and die entirely?
    {
        printf("Something is wrong! peer is larger than MAX_PEERS: %i\n", peer);
        return 0;
    }

    p = &peers[peer];

    if ((p->tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Can't create TCP socket\n");
        return 0;
    }

    if (setsockopt(p->tcp_fd, SOL_SOCKET, SO_REUSEADDR, &socket_opt_val, sizeof(int)))
        printf("Setting SO_REUSEADDR failed\n");

    if (fcntl(p->tcp_fd, F_SETFL, O_NONBLOCK))
        printf("Setting O_NONBLOCK failed\n");

    p->tcp.sin_family = AF_INET;

    // This should not be hardcoded to a magic number; per ns port data structure changes required
    p->tcp.sin_port = htons(53);

    p->tcp.sin_addr.s_addr = nameservers[ns];

    printf("connecting to %s on port %i\n", inet_ntoa(p->tcp.sin_addr), ntohs(p->tcp.sin_port));
    cs = connect(p->tcp_fd, (struct sockaddr*)&p->tcp, sizeof(struct sockaddr_in));
    if (cs != 0) perror("connect status:");

    // We should be in non-blocking mode now
    p->bl = 0;
    p->con = CONNECTING;

    return 1;
}

/* Returns 1 upon non-blocking connection; 0 upon serious error */
int peer_connected(uint peer)
{
    struct peer_t *p;
    int cs;

    if (peer > MAX_PEERS)
    {
        printf("Something is wrong! peer is larger than MAX_PEERS: %i\n", peer);
        return 0;
    }

    p = &peers[peer];

    cs = connect(p->tcp_fd, (struct sockaddr*)&p->tcp, sizeof(struct sockaddr_in));

    if (cs == 0) {
        p->con = CONNECTED;
        return 1;
    } else {
        printf("connection failed\n");
        close(p->tcp_fd);
        p->tcp_fd = -1;
        p->con = DEAD;
        return 0;
    }
}

/*
int peer_keepalive(uint peer)
{
	return 1;
}
*/

/* Returns 1 upon sent request; 0 upon serious error and 2 upon disconnect */
int peer_sendreq(uint peer, int req)
{
    struct peer_t *p;
    struct request_t *r;
    int ret;

    if (peer > MAX_PEERS)
    {
        printf("Something is wrong! peer is larger than MAX_PEERS: %i\n", peer);
        return 0;
    }

    if (req > MAX_REQUESTS)
    {
        printf("Something is wrong! peer is larger than MAX_PEERS: %i\n", peer);
        return 0;
    }

    p = &peers[peer];
    r = &requests[req];

    while ((ret = write(p->tcp_fd, r->b, (r->bl + 2))) < 0 && errno == EAGAIN);

    if (ret == 0) {
        close(p->tcp_fd);
        p->tcp_fd = -1;
        p->con = DEAD;
        printf("peer %d got disconnected\n", peer);
        return 2;
    }

    printf("peer_sendreq write attempt returned: %d\n", ret);
    return 1;
}

/* Returns -1 on error, returns 1 on something, returns 2 on something, returns 3 on disconnect. */
/* XXX This function needs a really serious re-write/audit/etc. */
int peer_readres(uint peer)
{
    struct peer_t *p;
    struct request_t *r;
    int ret;
    unsigned short int *ul;
    int id;
    int req;
    unsigned short int *l;
    int len;

    if (peer > MAX_PEERS)
    {
        printf("Something is wrong! peer is larger than MAX_PEERS: %i\n", peer);
        return -1;
    }

    p = &peers[peer];
    l = (unsigned short int*)p->b;

    while ((ret = read(p->tcp_fd, (p->b + p->bl), (1502 - p->bl))) < 0 && errno == EAGAIN);

    if (ret == 0) {
        close(p->tcp_fd);
        p->tcp_fd = -1;
        printf("peer %d got disconnected\n", peer);
        p->con = DEAD;
        return 3;
    }

    p->bl += ret;

    // get answer from receive buffer
processanswer:

    if (p->bl < 2) {
        return 2;
    }
    else {
        len = ntohs(*l);

        printf("r l=%d r=%d\n", len, p->bl-2);

        if ((len + 2) > p->bl)
            return 2;
    }

    printf("received answer %d bytes\n", p->bl);

    ul = (unsigned short int*)(p->b + 2);
    id = ntohs(*ul);

    if ((req = request_find(id)) == -1) {
        memmove(p->b, (p->b + len + 2), (p->bl - len - 2));
        p->bl -= len + 2;
        return 0;
    }
    r = &requests[req];

    // write back real id
    *ul = htons(r->rid);

    r->a.sin_family = AF_INET;
    while (sendto(udp_fd, (p->b + 2), len, 0, (struct sockaddr*)&r->a, sizeof(struct sockaddr_in)) < 0 && errno == EAGAIN);

    printf("forwarding answer (%d bytes)\n", len);

    memmove(p->b, p->b + len +2, p->bl - len - 2);
    p->bl -= len + 2;

    // mark as handled/unused
    r->id = 0;

    if (p->bl > 0) goto processanswer;

    return 1;
}

void peer_handleoutstanding(uint peer)
{
    int i;

    if (peer > MAX_PEERS)
    {
        printf("Something is wrong! peer is larger than MAX_PEERS: %i\n", peer);
    }

    for (i = 0; i < MAX_REQUESTS; i++) {
        if (requests[i].id != 0 && requests[i].active == WAITING) {
            requests[i].active = SENT;
            peer_sendreq(peer, i);
        }
    }
}

int peer_select(void)
{
	return 0;
}

int ns_select(void)
{
// This could use a real bit of randomness, I suspect
	return (rand()>>16) % num_nameservers;
}

int request_add(struct request_t *r)
{
	int pos = r->id % MAX_REQUESTS;
	int dst_peer;
	unsigned short int *ul;
	time_t ct = time(NULL);

	printf("adding new request (id=%d)\n", r->id);
	for (;;) {
		if (requests[pos].id == 0) {
			// this one is unused, take it
			break;
		}
		else {
			if (requests[pos].id == r->id) {
				if (memcmp((char*)&r->a, (char*)&requests[pos].a, sizeof(r->a)) == 0) {
					printf("hash position %d already taken by request with same id; dropping it\n", pos);
					return 0;
				}
				else {
					do {
						r->id = ((rand()>>16) % 0xffff);
					} while (r->id < 1);
					pos = r->id % MAX_REQUESTS;
					printf("NATing id (id was %d now is %d)\n", r->rid, r->id);
					continue;
				}
			}
			else if ((requests[pos].timeout + MAX_TIME) > ct) {
				// request timed out, take it
				break;
			}
			else {
				pos++;
				pos %= MAX_REQUESTS;
				if (pos == (r->id % MAX_REQUESTS)) {
					printf("no more free request slots, wow this is a busy node. dropping request!\n");
					return 0;
				}
			}
		}
	}

	r->timeout = time(NULL);
	
	// update id
	ul = (unsigned short int*)(r->b + 2);
	*ul = htons(r->id);
	
	printf("using request slot %d\n", pos);
	memcpy((char*)&requests[pos], (char*)r, sizeof(struct request_t));

	// nice feature to have: send request to multiple peers for speedup and reliability
	
	dst_peer = peer_select();
	if (peers[dst_peer].con == CONNECTED) {
		r->active = SENT;
		return peer_sendreq(dst_peer, pos);
	}
	else {
		return peer_connect(dst_peer, ns_select());
	}
}

int server(char *bind_ip, int bind_port)
{
	struct sockaddr_in udp;
	struct pollfd pfd[MAX_PEERS+1];
	int poll2peers[MAX_PEERS];
	int fr;
	int i;
	int pfd_num;
	struct request_t tmp;
	
	for (i = 0; i < MAX_PEERS; i++) {
		peers[i].tcp_fd = -1;
		poll2peers[i] = -1;
		peers[i].con = DEAD;
	}
	memset((char*)requests, 0, sizeof(requests)); // Why not bzero?

	// setup listing port - someday we may also want to listen on TCP just for fun
	if ((udp_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("can't create UDP socket\n");
		return(-1);
	}
	memset((char*)&udp, 0, sizeof(struct sockaddr_in)); // bzero love
	udp.sin_family = AF_INET;
	udp.sin_port = htons(bind_port);
	if (!inet_aton(bind_ip, (struct in_addr*)&udp.sin_addr)) {
		printf("is not a valid IPv4 address: %s\n", bind_ip);
		return(0); // Why is this 0?
	}
	if (bind(udp_fd, (struct sockaddr*)&udp, sizeof(struct sockaddr_in)) < 0) {
		close(udp_fd);
		printf("can't bind to %s:%d\n", bind_ip, bind_port);
		return(-1); // Perhaps this should be more useful?
	}

	// drop privileges
	if (!DEBUG) {
		setgid(NOGROUP);
		setuid(NOBODY);
	}
		
	for (;;) {
		// populate poll array
		for (pfd_num = 1, i = 0; i < MAX_PEERS; i++) {	
			if (peers[i].tcp_fd != -1) {
				pfd[pfd_num].fd = peers[i].tcp_fd;
				switch (peers[i].con) {
				case CONNECTED:
					pfd[pfd_num].events = POLLIN|POLLPRI;
					break;
                case DEAD:
                    pfd[pfd_num].events = POLLOUT|POLLERR;
                    break;
                case CONNECTING:
                    pfd[pfd_num].events = POLLOUT|POLLERR;
                    break;
                case CONNECTING2:
                    pfd[pfd_num].events = POLLOUT|POLLERR;
                    break;
				default:
					pfd[pfd_num].events = POLLOUT|POLLERR;
					break;
				}
				poll2peers[pfd_num-1] = i;
				pfd_num++;
			}
		}
	
		pfd[0].fd = udp_fd;
		pfd[0].events = POLLIN|POLLPRI;
		
		printf("watching %d file descriptors\n", pfd_num);
		
		fr = poll(pfd, pfd_num, -1);
		
		printf("%d file descriptors became ready\n", fr);

		// handle tcp connections
		for (i = 1; i < pfd_num; i++) {
			if (pfd[i].fd != -1 && ((pfd[i].revents & POLLIN) == POLLIN || 
					(pfd[i].revents & POLLPRI) == POLLPRI || (pfd[i].revents & POLLOUT) 
					== POLLOUT || (pfd[i].revents & POLLERR) == POLLERR)) {
				
				switch (peers[poll2peers[i-1]].con) {
				case CONNECTED:
					peer_readres(poll2peers[i-1]);
					break;
				case CONNECTING:
				case CONNECTING2:
					if (peer_connected(poll2peers[i-1])) {
						peer_handleoutstanding(poll2peers[i-1]);
					}
					break;
                case DEAD:
                    printf("peer %d in bad state\n", peers[poll2peers[i-1]].con);
                    break;
				default:
					printf("peer %d in bad state\n", peers[poll2peers[i-1]].con);
					break;
				}
			}
		}
	
		// handle port 53
		if ((pfd[0].revents & POLLIN) == POLLIN || (pfd[0].revents & POLLPRI) == POLLPRI) {
			unsigned short int *ul;
			
			memset((char*)&tmp, 0, sizeof(struct request_t));
			tmp.al = sizeof(struct sockaddr_in);
			
			while ((tmp.bl = recvfrom(udp_fd, tmp.b+2, 1500, 0, (struct sockaddr*)&tmp.a, &tmp.al)) < 0 && errno == EAGAIN);
			// get request id
			ul = (unsigned short int*) (tmp.b + 2);
			tmp.rid = tmp.id = ntohs(*ul);
			// get request length
			ul = (unsigned short int*)tmp.b;
			*ul = htons(tmp.bl);
			
			printf("received request of %d bytes, id = %d\n", tmp.bl, tmp.id);
			
			request_add(&tmp); // This should be checked, we're currently ignoring imporant returns
		}
	}
}

int load_nameservers(char *filename)
{
	FILE *fp;
    char line[MAX_LINE_SIZE] = {0};
	unsigned long int ns;


	if (!(fp = fopen(filename, "r"))) {
		printf("can't open %s\n", filename);
		return 0;
	}
	num_nameservers = 0;
	if (!(nameservers = malloc(sizeof(unsigned long int) * MAX_NAMESERVERS))) {
		fclose(fp);
		return 0;
	}
	
	if (!fp) return 0;
	while (fgets(line, MAX_LINE_SIZE, fp)) { // properly terminate line
		if (line[0] == '#' || line[0] == '\n' || line[0] == ' ') continue;
		line[strlen(line)-1] = 0; // This is a tautology - do not compute, know the end
		if (strstr(line, "192.168.") == line) continue;
		if (strstr(line, "127.") == line) continue;
		if (strstr(line, "10.") == line) continue;
		if (inet_pton(AF_INET, line, &ns)) {
			nameservers[num_nameservers] = ns;
			num_nameservers++;
			if (num_nameservers >= MAX_NAMESERVERS) {
				printf("stopped loading nameservers after first %d\n", MAX_NAMESERVERS);
				break;
			}
		}
		else {
			printf("%s: is not a valid IPv4 address\n", line);
		}
	}
	fclose(fp);
	nameservers = realloc(nameservers, sizeof(unsigned long int) * num_nameservers);
	printf("%d nameservers loaded\n", num_nameservers);
	
	return 1;
}

int main(int argc, char **argv)
{
	int opt;
	int debug = 0;
	int dochroot = 1;
	char resolvers[250] = {DEFAULT_RESOLVERS};
	char bind_ip[250] = {DEFAULT_BIND_IP};
	char chroot_dir[PATH_MAX] = {DEFAULT_CHROOT};
	char tsocks_conf[PATH_MAX];
	int log = 0;
	int bind_port = DEFAULT_BIND_PORT;
	int devnull;
	char pid_file[PATH_MAX] = {0};
    FILE *pf;
    int r;
	
	
	while ((opt = getopt(argc, argv, "lhdcC:b:f:p:P:")) != EOF) {
		switch (opt) {
		// log debug to file
		case 'l':
			log = 1;
			break;
		// debug
		case 'd':
			debug = 1;
			break;
		// DON'T chroot
		case 'c':
			dochroot = 0;
			break;
		// Chroot directory
		case 'C':
			strncpy(chroot_dir, optarg, sizeof(chroot_dir)-1);
			break;
		// PORT
		case 'p':
			bind_port = atoi(optarg);
			if (bind_port < 1) bind_port = DEFAULT_BIND_PORT;
			break;
		// config file
		case 'f':
			strncpy(resolvers, optarg, sizeof(resolvers)-1);
			break;
		// IP
		case 'b':
			strncpy(bind_ip, optarg, sizeof(bind_ip)-1);
			break;
		// PID file
		case 'P':
			strncpy(pid_file, optarg, sizeof(pid_file)-1);
			break;
		// help
		case 'h':
		default:
			printf("%s", HELP_STR);
			exit(0);
			break;
		}
	}

	srand(time(NULL)); // This should use OpenSSL in the future
	
	if (getuid() != 0 && (bind_port == DEFAULT_BIND_PORT || dochroot == 1)) {
		printf("ttdnsd must run as root to bind to port 53 and chroot(2)\n");
		exit(1);
	}

	if (!load_nameservers(resolvers)) { // perhaps we want to move this entirely into the chroot?
		printf("can't open resolvers file %s, will try again after chroot\n", resolvers);
	}

	devnull = open("/dev/null", O_RDWR); // Leaked fd?
	if (devnull < 0) {
		printf("can't open /dev/null, exit\n");
		exit(1);
	}

	// become a daemon
	if (!debug) {
		if (fork()) exit(0); // Could be clearer
		setsid(); // Safe?
	}

    /* Why does this happen before the chroot? */
	// write PID to file
	if (strlen(pid_file) > 0) {
		int pfd = open(pid_file, O_WRONLY|O_TRUNC|O_CREAT, 00644);
		if (pfd < 0) {
			printf("can't open pid file %s, exit\n", pid_file);
			exit(1);
		}
		pf = fdopen(pfd, "w");
		if (pf == NULL) {
			printf("can't reopen pid file %s, exit\n", pid_file);
			exit(1);
		}
		fprintf(pf, "%d", getpid());
		fclose(pf);
		close(pfd);
	}
	
	if (dochroot) {	
		if (chdir(chroot_dir)) {
			printf("can't chdir to %s, exit\n", chroot_dir);
			exit(1);
		}
		if (chroot(chroot_dir)) {
			printf("can't chroot to %s, exit\n", chroot_dir);
			exit(1);
		}
		// since we chroot, check for the tsocks config
        strncpy(tsocks_conf, getenv(TSOCKS_CONF_ENV), PATH_MAX-1);
        tsocks_conf[PATH_MAX-1] = '\0';
		if (access(tsocks_conf, R_OK)) { /* access() is a race condition and unsafe */
			printf("chroot=%s, can't access tsocks config at %s, exit\n", chroot_dir, tsocks_conf);
			exit(1);
		}
	}
		
	// privs will be dropped in server right after binding to port 53	
	
	if (log) {
		int lfd;
		lfd = open(DEFAULT_LOG, O_WRONLY|O_APPEND|O_CREAT, 00644);
		if (lfd < 0) {
			if (dochroot) printf("chroot=%s ", chroot_dir);
			printf("can't open log file %s, exit\n", DEFAULT_LOG);
			exit(1);
		}
		dup2(lfd, 1);
		dup2(lfd, 2);
		close(lfd);
		dup2(devnull, 0);
		close(devnull);
	}
	else if (!debug) {
		dup2(devnull, 0);
		dup2(devnull, 1);
		dup2(devnull, 2);
		close(devnull);
	}

    r = server(bind_ip, bind_port);
    if (r!=0)
        printf("something went wrong with the server %d\n", r);
    exit(r);
}
