/*	$NetBSD: rpcbind.c,v 1.3 2002/11/08 00:16:40 fvdl Exp $	*/
/*	$FreeBSD: src/usr.sbin/rpcbind/rpcbind.c,v 1.14 2004/11/07 04:32:51 dd Exp $ */

/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
/*
 * Copyright (c) 1984 - 1991 by Sun Microsystems, Inc.
 */

/* #ident	"@(#)rpcbind.c	1.19	94/04/25 SMI" */
#if 0
#ifndef lint
static	char sccsid[] = "@(#)rpcbind.c 1.35 89/04/21 Copyr 1984 Sun Micro";
#endif
#endif

/*
 * rpcbind.c
 * Implements the program, version to address mapping for rpc.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/file.h>
#include <libarpc/arpc.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <err.h>
#include <pwd.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include "rpcbind.h"

/* Global variables */
int debugging = 0;	/* Tell me what's going on */
int doabort = 0;	/* When debugging, do an abort on errors */
rpcblist_ptr list_rbl;	/* A list of version 3/4 rpcbind services */

/* who to suid to if -s is given */
#define RUN_AS  "daemon"

#define RPCBINDDLOCK "/var/run/arpcbind.lock"

int runasdaemon = 0;
int insecure = 0;
int oldstyle_local = 0;
int verboselog = 0;

char **hosts = NULL;
int nhosts = 0;
int on = 1;
int rpcbindlockfd;

#ifdef WARMSTART
/* Local Variable */
static int warmstart = 0;	/* Grab an old copy of registrations. */
#endif

ar_pmaplist_t *list_pml;	/* A list of version 2 rpcbind services */
char *udptrans;		/* Name of UDP transport */
char *tcptrans;		/* Name of TCP transport */
char *udp_uaddr;	/* Universal UDP address */
char *tcp_uaddr;	/* Universal TCP address */
ar_ioctx_t rpcbind_ioctx;
static char servname[] = "sunrpc";
static char superuser[] = "superuser";

int main __P((int, char *[]));

static int init_transport __P((ar_ioctx_t ioctx, ar_netid_t *nconf));
static int rbllist_add(arpcprog_t prog, arpcvers_t vers, ar_netid_t *nconf,
		       const arpc_addr_t *addr);
static void terminate __P((int));
static void parseargs __P((int, char *[]));

int
main(int argc, char *argv[])
{
	ar_netid_t *nconf;
	ar_netid_t *local;
	struct rlimit rl;
	ar_ioctx_t ioctx;
	int rc;
	int i;

	parseargs(argc, argv);

	rc = ar_ioctx_create(&ioctx);
	if (rc != 0) {
		fprintf(stderr, "create ioctx failed: %s\n", strerror(rc));
		exit(1);
	}
	rpcbind_ioctx = ioctx;

	/* Check that another rpcbind isn't already running. */
	if ((rpcbindlockfd = (open(RPCBINDDLOCK,
	    O_RDONLY|O_CREAT, 0444))) == -1)
		err(1, "%s", RPCBINDDLOCK);

	if(flock(rpcbindlockfd, LOCK_EX|LOCK_NB) == -1 && errno == EWOULDBLOCK)
		errx(1, "another arpcbind is already running. Aborting");

	getrlimit(RLIMIT_NOFILE, &rl);
	if (rl.rlim_cur < 128) {
		if (rl.rlim_max <= 128)
			rl.rlim_cur = rl.rlim_max;
		else
			rl.rlim_cur = 128;
		setrlimit(RLIMIT_NOFILE, &rl);
	}
	openlog("arpcbind", LOG_CONS, LOG_DAEMON);
	if (geteuid()) { /* This command allowed only to root */
		fprintf(stderr, "Sorry. You are not superuser\n");
		exit(1);
	}
	udptrans = "";
	tcptrans = "";

	rc = ar_str2netid(ioctx, "local", &local);
	if (rc != 0) {
		syslog(LOG_ERR, "%s: can't find local transport\n", argv[0]);
		exit(1);
	}

	init_transport(ioctx, local);

	for (i = 0; ; i++) {
		rc = ar_idx2netid(ioctx, i, &nconf);
		if (rc != 0) {
			syslog(LOG_ERR, "%s: get transport %d failed: %s\n", 
			       argv[0], i, strerror(rc));
			continue;
		}
		if (!nconf) {
			/* end of list */
			break;
		}

		if (nconf == local) {
			/* already initialized */
			continue;
		}
		init_transport(ioctx, nconf);
	}

	/* catch the usual termination signals for graceful exit */
	(void) signal(SIGCHLD, reap);
	(void) signal(SIGINT, terminate);
	(void) signal(SIGTERM, terminate);
	(void) signal(SIGQUIT, terminate);
	/* ignore others that could get sent */
	(void) signal(SIGPIPE, SIG_IGN);
	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGUSR1, SIG_IGN);
	(void) signal(SIGUSR2, SIG_IGN);
#ifdef WARMSTART
	if (warmstart) {
		read_warmstart();
	}
#endif
	if (debugging) {
		printf("arpcbind debugging enabled.");
		if (doabort) {
			printf("  Will abort on errors!\n");
		} else {
			printf("\n");
		}
	} else {
		if (daemon(0, 0))
			err(1, "fork failed");
	}

	if (runasdaemon) {
		struct passwd *p;

		if((p = getpwnam(RUN_AS)) == NULL) {
			syslog(LOG_ERR, "cannot get uid of daemon: %m");
			exit(1);
		}
		if (setuid(p->pw_uid) == -1) {
			syslog(LOG_ERR, "setuid to daemon failed: %m");
			exit(1);
		}
	}

	network_init();

	ar_ioctx_run(ioctx);
	syslog(LOG_ERR, "svc_run returned unexpectedly");
	rpcbind_abort();
	/* NOTREACHED */

	return 0;
}


static int
add_host(ar_ioctx_t ioctx, ar_netid_t *nconf, const char *host, 
	 struct addrinfo *hints)
{
	u_int32_t host_addr[4];  /* IPv4 or IPv6 */
	struct addrinfo *res = NULL;
	struct sockaddr *sa;
	struct sockaddr_un sun;
	ar_svc_xprt_t *my_xprt = NULL;
	bool_t ipv6_only = FALSE;
	ar_pmaplist_t *pml;
	arpc_addr_t addr;
	char *errstr;
	arpc_err_t aerr;
	int addrlen;
	int aicode;
	int err;

	addr.buf = NULL;
	pml = NULL;

	switch (hints->ai_family) {
	case AF_INET:
		if (inet_pton(AF_INET, host, host_addr) == 1) {
			hints->ai_flags &= AI_NUMERICHOST;
		} else {
			/*
			 * Skip if we have an AF_INET6 address.
			 */
			if (inet_pton(AF_INET6, host, host_addr) == 1) {
				return 0;
			}
		}
		break;
	case AF_INET6:
		if (inet_pton(AF_INET6, host, host_addr) == 1) {
			hints->ai_flags &= AI_NUMERICHOST;
		} else {
			/*
			 * Skip if we have an AF_INET address.
			 */
			if (inet_pton(AF_INET, host, host_addr) == 1) {
				return 0;
			}
		}
		ipv6_only = TRUE;
		break;
	default:
		break;
	}

	/*
	 * If no hosts were specified, just bind to INADDR_ANY
	 */
	if (strcmp("*", host) == 0) {
		host = NULL;
	}

	if ((strcmp(nconf->an_netid, "local") == 0) ||
	    (strcmp(nconf->an_netid, "unix") == 0)) {
		memset(&sun, 0, sizeof sun);
		sun.sun_family = AF_LOCAL;
		unlink(_PATH_RPCBINDSOCK);
		strlcpy(sun.sun_path, _PATH_RPCBINDSOCK, sizeof(sun.sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sun.sun_len = SUN_LEN(&sun);
#endif
		addrlen = sizeof (struct sockaddr_un);
		sa = (struct sockaddr *)&sun;
		res = NULL;
	} else {
		aicode = getaddrinfo(host, servname, hints, &res);
		if (aicode != 0) {
			syslog(LOG_ERR,
			       "cannot get local address for %s: %s",
			       nconf->an_netid, gai_strerror(aicode));
			return 0;
		}
		sa = (struct sockaddr *)res->ai_addr;
		addrlen = res->ai_addrlen;
	}
	memset(&addr, 0, sizeof(addr));
	addr.len = addrlen;
	addr.maxlen = addrlen;
	addr.buf = malloc(addrlen);
	if (!addr.buf) {
		syslog(LOG_ERR,
		       "cannot allocate memory for %s address",
		       nconf->an_netid);
		err = ENOMEM;
		goto error;
	}
	memcpy(addr.buf, sa, addrlen);
	if (res != NULL) {
		freeaddrinfo(res);
		res = NULL;
	}
		
#ifdef ND_DEBUG
	if (debugging) {
		/*
		 * for debugging print out our universal
		 * address
		 */
		char *uaddr;

		err = ar_taddr2uaddr_af(nconf->an_family, &addr, &uaddr);
		if (err == 0) {
			fprintf(stderr,
				"arpcbind : my address is %s\n", uaddr);
			free(uaddr);
		}
	}
#endif
	err = ar_svc_tli_create(ioctx, nconf->an_netid, &addr, NULL, &aerr, 
				&my_xprt);
	if (err != 0) {
		errstr = ar_astrerror(&aerr);
		syslog(LOG_ERR, "%s: could not create service: %s",
		       nconf->an_netid, errstr ? errstr : "<unknown>");
		goto error;
	}

	/*
	 * Register both the versions for tcp/ip, udp/ip and local.
	 */
	if ((nconf->an_family == AF_INET && 
	     (nconf->an_proto == IPPROTO_TCP || 
	      nconf->an_proto == IPPROTO_UDP)) || 
	    (strcmp(nconf->an_netid, "unix") == 0) ||
	    (strcmp(nconf->an_netid, "local") == 0)) {
		err = ar_svc_reg(my_xprt, pmap_lookup, PMAPPROG, PMAPVERS);
		if (err != 0) {
			syslog(LOG_ERR, "could not register on %s",
			       nconf->an_netid);
			goto error;
		}

		/* Also add version 2 stuff to arpcbind list */
		err = rbllist_add(PMAPPROG, PMAPVERS, nconf, &addr);
		if (err != 0) {
			syslog(LOG_ERR, "could not list on %s",
			       nconf->an_netid);
			goto error;
		}

		pml = malloc(sizeof(*pml));
		if (pml == NULL) {
			err = ENOMEM;
			syslog(LOG_ERR, "no memory!");
			goto error;
		}
		memset(pml, 0, sizeof(*pml));

		pml->pml_map.pm_prog = PMAPPROG;
		pml->pml_map.pm_vers = PMAPVERS;
		pml->pml_map.pm_port = PMAPPORT;
		if (nconf->an_family == AF_INET &&
		    nconf->an_proto == IPPROTO_TCP) {
			if (tcptrans[0]) {
				err = EBUSY;
				syslog(LOG_ERR,
				"cannot have more than one TCP transport");
				goto error;
			}
			tcptrans = strdup(nconf->an_netid);
			if (!tcptrans) {
				err = ENOMEM;
				syslog(LOG_ERR, "no memory for pmap map");
				goto error;
			}
			pml->pml_map.pm_prot = IPPROTO_TCP;

			/* Let's snarf the universal address */
			/* "h1.h2.h3.h4.p1.p2" */
			err = ar_taddr2uaddr_af(nconf->an_family, 
						&addr, &tcp_uaddr);
			if (err != 0) {
				syslog(LOG_ERR, "no memory for pmap map");
				goto error;
			}
		} else if (nconf->an_family == AF_INET &&
			   nconf->an_proto == IPPROTO_UDP) {
			if (udptrans[0]) {
				err = EBUSY;
				syslog(LOG_ERR,
				"cannot have more than one UDP transport");
				goto error;
			}
			udptrans = strdup(nconf->an_netid);
			if (!udptrans) {
				err = ENOMEM;
				syslog(LOG_ERR, "no memory for pmap map");
				goto error;
			}
			pml->pml_map.pm_prot = IPPROTO_UDP;

			/* Let's snarf the universal address */
			/* "h1.h2.h3.h4.p1.p2" */
			err = ar_taddr2uaddr_af(nconf->an_family, 
						&addr, &udp_uaddr);
			if (err != 0) {
				syslog(LOG_ERR, "no memory for pmap map");
				goto error;
			}
		}
		pml->pml_next = list_pml;
		list_pml = pml;
		pml = NULL;

		/* Add version 3 information */
		pml = malloc(sizeof(*pml));
		if (pml == NULL) {
			err = ENOMEM;
			syslog(LOG_ERR, "no memory!");
			goto error;
		}
		pml->pml_map = list_pml->pml_map;
		pml->pml_map.pm_vers = RPCBVERS;
		pml->pml_next = list_pml;
		list_pml = pml;
		pml = NULL;

		/* Add version 4 information */
		pml = malloc(sizeof(*pml));
		if (pml == NULL) {
			err = ENOMEM;
			syslog(LOG_ERR, "no memory!");
			goto error;
		}
		pml->pml_map = list_pml->pml_map;
		pml->pml_map.pm_vers = RPCBVERS4;
		pml->pml_next = list_pml;
		list_pml = pml;
		pml = NULL;
	}

	/* version 3 registration */
	err = ar_svc_reg(my_xprt, rpcbprog_3_lookup, RPCBPROG, RPCBVERS);
	if (err != 0) {
		syslog(LOG_ERR, "could not register %s version 3",
		       nconf->an_netid);
		goto error;
	}
	err = rbllist_add(RPCBPROG, RPCBVERS, nconf, &addr);
	if (err != 0) {
		syslog(LOG_ERR, "could not list on %s", nconf->an_netid);
		goto error;
	}

	/* version 4 registration */
	err = ar_svc_reg(my_xprt, rpcbprog_4_lookup, RPCBPROG, RPCBVERS4);
	if (err != 0) {
		syslog(LOG_ERR, "could not register %s version 4",
		       nconf->an_netid);
		goto error;
	}
	err = rbllist_add(RPCBPROG, RPCBVERS4, nconf, &addr);
	if (err != 0) {
		syslog(LOG_ERR, "could not list on %s", nconf->an_netid);
		goto error;
	}

	free(addr.buf);
	return 0;
		
error:
	if (pml) {
		free(pml);
	}
	if (my_xprt != NULL) {
		ar_svc_destroy(my_xprt);
	}
	if (addr.buf != NULL) {
		free(addr.buf);
	}
	if (res != NULL) {
		freeaddrinfo(res);
	}
	return err;
}

/*
 * Adds the entry into the arpcbind database.
 * If PORTMAP, then for UDP and TCP, it adds the entries for version 2 also
 * Returns 0 if succeeds, else fails
 */
static int
init_transport(ar_ioctx_t ioctx, ar_netid_t *nconf)
{
	struct addrinfo hints;
	ar_sockinfo_t si;
	int nhostsbak;
	int status;	/* bound checking ? */
	int checkbind;
	int err;

	if ((nconf->an_semantics != AR_SEM_CLTS) &&
	    (nconf->an_semantics != AR_SEM_COTS)) {
		return (1);	/* not my type */
	}

	err = ar_netid2sockinfo(nconf, &si);
	if (err != 0) {
		syslog(LOG_ERR, "cannot get information for %s",
		       nconf->an_netid);
		return (1);
	}

	/* Get arpcbind's address on this transport */
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = si.si_af;
	hints.ai_socktype = si.si_socktype;
	hints.ai_protocol = si.si_proto;

	if (nconf->an_semantics == AR_SEM_CLTS) {
		/*
		 * If no hosts were specified, just bind to INADDR_ANY.
		 * Otherwise make sure 127.0.0.1 is added to the list.
		 */
		if (nhosts <= 0) {
			err = add_host(ioctx, nconf, "*", &hints);
		} else if (hints.ai_family == AF_INET) {
			err = add_host(ioctx, nconf, "127.0.0.1", &hints);
		} else if (hints.ai_family == AF_INET6) {
			err = add_host(ioctx, nconf, "::1", &hints);
		} else {
			return 1;
		}
		if (err != 0) {
			return 1;
		}

		nhostsbak = nhosts;

	       /*
		* Bind to specific IPs if asked to
		*/
		checkbind = 1;
		while (nhostsbak > 0) {
			--nhostsbak;
			
			err = add_host(ioctx, nconf, hosts[nhostsbak], 
				       &hints);
			if (err != 0) {
				return 1;
			}
		}
	} else {
		/* TCP can't bind per interface currently... */
		err = add_host(ioctx, nconf, "*", &hints);
		if (err != 0) {
			return 1;
		}
	}

	/* decide if bound checking works for this transport */
	status = add_bndlist(nconf);
#ifdef BIND_DEBUG
	if (debugging) {
		if (status < 0) {
			fprintf(stderr, "Error in finding bind status "
				"for %s\n", nconf->nc_netid);
		} else if (status == 0) {
			fprintf(stderr, "check binding for %s\n",
				nconf->nc_netid);
		} else if (status > 0) {
			fprintf(stderr, "No check binding for %s\n",
				nconf->nc_netid);
		}
	}
#endif
	return (0);
}

static int
rbllist_add(arpcprog_t prog, arpcvers_t vers, ar_netid_t *nconf,
	    const arpc_addr_t *addr)
{
	rpcblist_ptr rbl;
	int err;

	rbl = malloc(sizeof(*rbl));
	if (rbl == NULL) {
		syslog(LOG_ERR, "no memory!");
		return ENOMEM;
	}
	memset(rbl, 0, sizeof(*rbl));

	rbl->rpcb_map.r_prog = prog;
	rbl->rpcb_map.r_vers = vers;
	err = ar_taddr2uaddr_af(nconf->an_family, addr, &rbl->rpcb_map.r_addr);
	if (err != 0) {
		free(rbl);
		return err;
	}
	rbl->rpcb_map.r_netid = strdup(nconf->an_netid);
	rbl->rpcb_map.r_owner = strdup(superuser);
	if (!rbl->rpcb_map.r_netid ||
	    !rbl->rpcb_map.r_owner) {
		free(rbl->rpcb_map.r_addr);
		rbl->rpcb_map.r_addr = NULL;
		if (!rbl->rpcb_map.r_netid) {
			free(rbl->rpcb_map.r_netid);
		}
		rbl->rpcb_map.r_netid = NULL;
		if (!rbl->rpcb_map.r_owner) {
			free(rbl->rpcb_map.r_owner);
		}
		rbl->rpcb_map.r_owner = NULL;
		free(rbl);
		return ENOMEM;
	}
	rbl->rpcb_next = list_rbl;	/* Attach to global list */
	list_rbl = rbl;
	return 0;
}

/*
 * Catch the signal and die
 */
static void
terminate(int dummy)
{
	close(rpcbindlockfd);
#ifdef WARMSTART
	syslog(LOG_ERR,
		"rpcbind terminating on signal. Restart with \"rpcbind -w\"");
	write_warmstart();	/* Dump yourself */
#endif
	exit(2);
}

void
rpcbind_abort()
{
#ifdef WARMSTART
	write_warmstart();	/* Dump yourself */
#endif
	abort();
}

/* get command line options */
static void
parseargs(int argc, char *argv[])
{
	int c;

#ifdef WARMSTART
#define	WSOP	"w"
#else
#define	WSOP	""
#endif
	while ((c = getopt(argc, argv, "adh:iLls" WSOP)) != -1) {
		switch (c) {
		case 'a':
			doabort = 1;	/* when debugging, do an abort on */
			break;		/* errors; for rpcbind developers */
					/* only! */
		case 'd':
			debugging = 1;
			break;
		case 'h':
			++nhosts;
			hosts = realloc(hosts, nhosts * sizeof(char *));
			if (hosts == NULL)
				errx(1, "Out of memory");
			hosts[nhosts - 1] = strdup(optarg);
			if (hosts[nhosts - 1] == NULL)
				errx(1, "Out of memory");
			break;
		case 'i':
			insecure = 1;
			break;
		case 'L':
			oldstyle_local = 1;
			break;
		case 'l':
			verboselog = 1;
			break;
		case 's':
			runasdaemon = 1;
			break;
#ifdef WARMSTART
		case 'w':
			warmstart = 1;
			break;
#endif
		default:	/* error */
			fprintf(stderr,
			    "usage: arpcbind [-adiLls%s] [-h bindip]\n",
			    WSOP);
			exit (1);
		}
	}
	if (doabort && !debugging) {
	    fprintf(stderr,
		"-a (abort) specified without -d (debugging) -- ignored.\n");
	    doabort = 0;
	}
#undef WSOP
}

void
reap(int dummy)
{
	int save_errno = errno;
 
	while (wait3(NULL, WNOHANG, NULL) > 0)
		;       
	errno = save_errno;
}

void
toggle_verboselog(int dummy)
{
	verboselog = !verboselog;
}
