/*	$NetBSD: rpcinfo.c,v 1.15 2000/10/04 20:09:05 mjl Exp $	*/

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
 * Copyright (c) 1986 - 1991 by Sun Microsystems, Inc.
 */

/* #ident	"@(#)rpcinfo.c	1.18	93/07/05 SMI" */

#if 0
#ifndef lint
static char sccsid[] = "@(#)rpcinfo.c 1.16 89/04/05 Copyr 1986 Sun Micro";
#endif
#endif

#include "compat.h"
__FBSDID("$FreeBSD: src/usr.bin/rpcinfo/rpcinfo.c,v 1.17 2004/03/11 10:22:25 bde Exp $");

/*
 * rpcinfo: ping a particular rpc program
 * 	or dump the the registered programs on the remote machine.
 */

/*
 * We are for now defining PORTMAP here.  It doesnt even compile
 * unless it is defined.
 */

/*
 * If PORTMAP is defined, rpcinfo will talk to both portmapper and
 * rpcbind programs; else it talks only to rpcbind. In the latter case
 * all the portmapper specific options such as -u, -t, -p become void.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libarpc/arpc.h>
#include <libarpc/arpcent.h>
#include <libarpc/pmap_clnt.h>

#include "rpcb_prot.h"
#include "pmap_prot.h"

#define MAXHOSTLEN 256
#define	MIN_VERS	((u_long) 0)
#define	MAX_VERS	((u_long) 4294967295UL)
#define	UNKNOWN		"unknown"

/*
 * Functions to be performed.
 */
#define	NONE		0	/* no function */
#define	PMAPDUMP	1	/* dump portmapper registrations */
#define	TCPPING		2	/* ping TCP service */
#define	UDPPING		3	/* ping UDP service */
#define	BROADCAST	4	/* ping broadcast service */
#define	DELETES		5	/* delete registration for the service */
#define	ADDRPING	6	/* pings at the given address */
#define	PROGPING	7	/* pings a program on a given host */
#define	RPCBDUMP	8	/* dump rpcbind registrations */
#define	RPCBDUMP_SHORT	9	/* dump rpcbind registrations - short version */
#define	RPCBADDRLIST	10	/* dump addr list about one prog */
#define	RPCBGETSTAT	11	/* Get statistics */

struct netidlist {
	char *netid;
	struct netidlist *next;
};

struct verslist {
	int vers;
	struct verslist *next;
};

struct rpcbdump_short {
	u_long prog;
	struct verslist *vlist;
	struct netidlist *nlist;
	struct rpcbdump_short *next;
	char *owner;
};


static char servname[] = "sunrpc";

static void 	ip_ping(ar_ioctx_t ioctx, u_short portnum, 
			char *trans, int argc, char **argv);
static ar_client_t *clnt_com_create(ar_ioctx_t ioctx,
				    struct sockaddr_in *addr, 
				    u_long prog, u_long vers, char *trans);
static void	pmapdump(ar_ioctx_t ioctx, int, char **);
static void	get_inet_address(struct sockaddr_in *, char *);

#if 0
static bool_t	reply_proc(void *, arpc_addr_t *, ar_netid_t *);
#endif
static void	brdcst(ar_ioctx_t, int, char **);
static void	addrping(ar_ioctx_t ioctx, char *, char *, int, char **);
static void	progping(ar_ioctx_t ioctx, char *, int, char **);
static ar_client_t	*clnt_addr_create(ar_ioctx_t ioctx, char *, 
					  const char *, u_long, u_long);
static ar_client_t   *clnt_rpcbind_create(ar_ioctx_t ioctx, char *, int, arpc_addr_t **, char **netidstr);
static ar_client_t   *getclnthandle(ar_ioctx_t ioctx, char *, const char *,
				    u_long, arpc_addr_t **);
static ar_client_t *local_rpcb(ar_ioctx_t ioctx, u_long prog, u_long vers);
static int	pstatus(ar_ioctx_t, u_long, u_long, const arpc_err_t *);
static void	rpcbdump(ar_ioctx_t ioctx, int, char *, int, char **);
static void	rpcbgetstat(ar_ioctx_t ioctx, int, char **);
static void	rpcbaddrlist(ar_ioctx_t ioctx, char *, int, char **);
static void	deletereg(char *, int, char **);
static void	print_rmtcallstat(int, rpcb_stat *);
static void	print_getaddrstat(int, rpcb_stat *);
static void	usage(void);
static u_long	getprognum(char *);
static u_long	getvers(char *);
static char	*spaces(int);
static bool_t	add_version(struct rpcbdump_short *, u_long);
static bool_t	add_netid(struct rpcbdump_short *, char *);

int
main(int argc, char **argv)
{
	register int c;
	int errflg;
	int function;
	char *netid = NULL;
	char *address = NULL;
	char *strptr;
	u_short portnum = 0;
	ar_ioctx_t ioctx;
	int rc;

	function = NONE;
	errflg = 0;
	while ((c = getopt(argc, argv, "a:bdlmn:pstT:u")) != -1) {
		switch (c) {
		case 'p':
			if (function != NONE)
				errflg = 1;
			else
				function = PMAPDUMP;
			break;

		case 't':
			if (function != NONE)
				errflg = 1;
			else
				function = TCPPING;
			break;

		case 'u':
			if (function != NONE)
				errflg = 1;
			else
				function = UDPPING;
			break;

		case 'n':
			portnum = (u_short) strtol(optarg, &strptr, 10);
			if (strptr == optarg || *strptr != '\0')
				errx(1, "%s is illegal port number", optarg);
			break;
		case 'a':
			address = optarg;
			if (function != NONE)
				errflg = 1;
			else
				function = ADDRPING;
			break;
		case 'b':
			if (function != NONE)
				errflg = 1;
			else
				function = BROADCAST;
			break;

		case 'd':
			if (function != NONE)
				errflg = 1;
			else
				function = DELETES;
			break;

		case 'l':
			if (function != NONE)
				errflg = 1;
			else
				function = RPCBADDRLIST;
			break;

		case 'm':
			if (function != NONE)
				errflg = 1;
			else
				function = RPCBGETSTAT;
			break;

		case 's':
			if (function != NONE)
				errflg = 1;
			else
				function = RPCBDUMP_SHORT;
			break;

		case 'T':
			netid = optarg;
			break;
		case '?':
			errflg = 1;
			break;
		}
	}

	if (errflg || ((function == ADDRPING) && !netid)) {
		usage();
	}

	if (function == NONE) {
		if (argc - optind > 1) {
			function = PROGPING;
		} else {
			function = RPCBDUMP;
		}
	}

	rc = ar_ioctx_create(&ioctx);
	if (rc != 0) {
		fprintf(stderr, "unable to create io context: %s\n", 
			strerror(rc));
		return 1;
	}

	switch (function) {
	case PMAPDUMP:
		if (portnum != 0)
			usage();
		pmapdump(ioctx, argc - optind, argv + optind);
		break;

	case UDPPING:
		ip_ping(ioctx, portnum, "udp", argc - optind, argv + optind);
		break;

	case TCPPING:
		ip_ping(ioctx, portnum, "tcp", argc - optind, argv + optind);
		break;
	case BROADCAST:
		brdcst(ioctx, argc - optind, argv + optind);
		break;
	case DELETES:
		deletereg(netid, argc - optind, argv + optind);
		break;
	case ADDRPING:
		addrping(ioctx, address, netid, argc - optind, argv + optind);
		break;
	case PROGPING:
		progping(ioctx, netid, argc - optind, argv + optind);
		break;
	case RPCBDUMP:
	case RPCBDUMP_SHORT:
		rpcbdump(ioctx, function, netid, argc - optind, argv + optind);
		break;
	case RPCBGETSTAT:
		rpcbgetstat(ioctx, argc - optind, argv + optind);
		break;
	case RPCBADDRLIST:
		rpcbaddrlist(ioctx, netid, argc - optind, argv + optind);
		break;
	}

	ar_ioctx_destroy(ioctx);

	return (0);
}

typedef struct create_stat_s {
	bool_t done;
	arpc_createerr_t cerr;
} create_stat_t;

static void
clnt_com_create_cb(ar_client_t *clnt, void *arg, 
		   const arpc_createerr_t *errp)
{
	arpcprog_t prog;
	arpcvers_t vers;
	create_stat_t *cstat;
	char *errstr;

	if (!ar_clnt_control(clnt, AR_CLGET_VERS, &vers)) {
		vers = -1;
	}

	if (!ar_clnt_control(clnt, AR_CLGET_PROG, &prog)) {
		prog = -1;
	}

	if (errp->cf_stat != ARPC_SUCCESS) {
		errstr = ar_astrcreateerror(errp);
		fprintf(stderr, "program %d version %d is not available: %s\n",
			prog, vers, errstr != NULL ? errstr : "<unknown>");
		if (errstr) {
			free(errstr);
		}
	}

	cstat = (create_stat_t *)arg;
	if (cstat != NULL) {
		cstat->done = TRUE;
		cstat->cerr = *errp;
	}
}

static ar_client_t *
local_rpcb(ar_ioctx_t ioctx, u_long prog, u_long vers)
{
	ar_netid_t *nconf;
	ar_client_t *clnt;
	struct sockaddr_un sun;
	arpc_addr_t addr;
	ar_clnt_attr_t attr;
	arpc_createerr_t cerr;
	int err;
	int idx;
	
	for (idx = 0;; idx++) {
		err = ar_idx2netid(ioctx, idx, &nconf);
		if (err != 0) {
			return NULL;
		}
		if (!nconf) {
			return NULL;
		}
		if (strcmp(nconf->an_netid, "local") == 0) {
			break;
		}
	}

	sun.sun_family = AF_LOCAL;
	strlcpy(sun.sun_path, _PATH_RPCBINDSOCK, sizeof(sun.sun_path));
	addr.buf = (char *)&sun;
	addr.len = sizeof(sun);
	addr.maxlen = sizeof(sun);

	err = ar_clnt_attr_init(&attr);
	if (err != 0) {
		return NULL;
	}
	
	err = ar_clnt_attr_set_conncb(&attr, &clnt_com_create_cb, NULL);
	if (err != 0) {
		ar_clnt_attr_destroy(&attr);
		return NULL;
	}

	err = ar_clnt_tli_create(ioctx, nconf->an_netid, &addr, prog, vers, 
				 &attr, &cerr, &clnt);
	ar_clnt_attr_destroy(&attr);
	if (err != 0) {
		return NULL;
	}

	return clnt;
}


static ar_client_t *
clnt_com_create(ar_ioctx_t ioctx, struct sockaddr_in *addr, 
		u_long prog, u_long vers, char *trans)
{
	ar_client_t *clnt;
	arpc_createerr_t cerr;
	ar_clnt_attr_t attr;
	arpc_addr_t a;
	char *errstr;
	int err;

	a.buf = (char *)addr;
	a.len = sizeof(*addr);
	a.maxlen = sizeof(*addr);

	err = ar_clnt_attr_init(&attr);
	if (err != 0) {
		return NULL;
	}
	
	err = ar_clnt_attr_set_conncb(&attr, &clnt_com_create_cb, NULL);
	if (err != 0) {
		ar_clnt_attr_destroy(&attr);
		return NULL;
	}

	err = ar_clnt_tli_create(ioctx, trans, &a, prog, vers, &attr,
				 &cerr, &clnt);
	ar_clnt_attr_destroy(&attr);
	if (err != 0) {
		errstr = ar_astrcreateerror(&cerr);
		fprintf(stderr, "program %lu version %lu "
			"is not available: %s\n", prog, vers, 
			errstr != NULL ? errstr : "<unknown>");
		if (errstr) {
			free(errstr);
		}
		exit(1);
		return NULL;
	}

	return (clnt);
}

/*
 * If portnum is 0, then go and get the address from portmapper, which happens
 * transparently through clnt*_create(); If version number is not given, it
 * tries to find out the version number by making a call to version 0 and if
 * that fails, it obtains the high order and the low order version number. If
 * version 0 calls succeeds, it tries for MAXVERS call and repeats the same.
 */
static void
ip_ping(ar_ioctx_t ioctx, u_short portnum, char *trans, int argc, char **argv)
{
	ar_client_t *client;
	struct timespec to;
	struct sockaddr_in addr;
	u_long prognum, vers, minvers, maxvers;
	arpc_err_t rpcerr;
	ar_stat_t rpc_stat;
	int failure = 0;

	if (argc < 2 || argc > 3) {
		usage();
	}
	to.tv_sec = 10;
	to.tv_nsec = 0;
	prognum = getprognum(argv[1]);
	get_inet_address(&addr, argv[0]);
	if (argc == 2) {	/* Version number not known */
		/*
		 * A call to version 0 should fail with a program/version
		 * mismatch, and give us the range of versions supported.
		 */
		vers = MIN_VERS;
	} else {
		vers = getvers(argv[2]);
	}
	addr.sin_port = htons(portnum);
	client = clnt_com_create(ioctx, &addr, prognum, vers, trans);
	if (!client) {
		exit(1);
		return;
	}

	rpc_stat = ar_clnt_call(client, AR_NULLPROC,
				(axdrproc_t)axdr_void, NULL,
				(axdrproc_t)axdr_void, NULL, 0, &to, &rpcerr);
	ar_clnt_destroy(client);
	if (argc != 2) {
		/* Version number was known */
		if (pstatus(ioctx, prognum, vers, &rpcerr) < 0) {
			exit(1);
		}
		return;
	}
	/* Version number not known */
	if (rpcerr.re_status != ARPC_PROGVERSMISMATCH) {
		if (rpcerr.re_status == ARPC_SUCCESS) {
			fprintf(stderr, "expected prog version mismatch "
				"on vers 0..\n");
		} else {
			pstatus(ioctx, prognum, vers, &rpcerr);
		}			
		exit(1);
	}

	minvers = rpcerr.re_vers.low;
	maxvers = rpcerr.re_vers.high;

	for (vers = minvers; vers <= maxvers; vers++) {
		addr.sin_port = htons(portnum);
		client = clnt_com_create(ioctx, &addr, prognum, vers, trans);
		if (!client) {
			exit(1);
			return;
		}
		rpc_stat = ar_clnt_call(client, AR_NULLPROC, 
					(axdrproc_t)axdr_void, NULL,
					(axdrproc_t)axdr_void, NULL, 0, 
					&to, &rpcerr);
		ar_clnt_destroy(client);

		if (pstatus(ioctx, prognum, vers, &rpcerr) < 0) {
			failure = 1;
		}
	}
	if (failure) {
		exit(1);
	}
	return;
}

/*
 * Dump all the portmapper registerations
 */
static void
pmapdump(ar_ioctx_t ioctx, int argc, char **argv)
{
	struct sockaddr_in server_addr;
	ar_pmaplist_t *head = NULL;
	struct timespec minutetimeout;
	register ar_client_t *client;
	struct rpcent *rpc;
	ar_stat_t clnt_st;
	arpc_err_t err;
	char *errstr;
	char *host;

	if (argc > 1) {
		usage();
	}
	if (argc == 1) {
		host = argv[0];
		get_inet_address(&server_addr, host);
		server_addr.sin_port = htons(PMAPPORT);
		client = clnt_com_create(ioctx, &server_addr, 
					 PMAPPROG, PMAPVERS, "tcp");
	} else {
		client = local_rpcb(ioctx, PMAPPROG, PMAPVERS);
	}
	if (client == NULL) {
		fprintf(stderr, "rpcinfo: can't contact portmapper\n");
		exit(1);
	}

	minutetimeout.tv_sec = 60;
	minutetimeout.tv_nsec = 0;

	clnt_st = ar_clnt_call(client, AR_PMAPPROC_DUMP, (axdrproc_t)axdr_void,
			       NULL, (axdrproc_t)axdr_ar_pmaplist_ptr, 
			       (char *)&head, sizeof(head), 
			       &minutetimeout, &err);
	if ((clnt_st == ARPC_PROGVERSMISMATCH) ||
	    (clnt_st == ARPC_PROGUNAVAIL)) {
		if (err.re_vers.low > PMAPVERS) {
			warnx("%s does not support portmapper.  "
			      "Try rpcinfo %s instead", host, host);
		}
		exit(1);
	}
	if (clnt_st != ARPC_SUCCESS) {
		errstr = ar_astrerror(&err);
		fprintf(stderr, "rpcinfo: can't contact portmapper: %s\n",
			errstr != NULL ? errstr : "<unknown>");
		if (errstr) {
			free(errstr);
		}
		exit(1);
	}
	if (head == NULL) {
		printf("No remote programs registered.\n");
	} else {
		printf("   program vers proto   port  service\n");
		for (; head != NULL; head = head->pml_next) {
			printf("%10ld%5ld",
				head->pml_map.pm_prog,
				head->pml_map.pm_vers);
			if (head->pml_map.pm_prot == IPPROTO_UDP) {
				printf("%6s", "udp");
			} else if (head->pml_map.pm_prot == IPPROTO_TCP) {
				printf("%6s", "tcp");
			} else if (head->pml_map.pm_prot == 0) {
				printf("%6s", "local");
			} else {
				printf("%6ld", head->pml_map.pm_prot);
			}
			printf("%7ld", head->pml_map.pm_port);
			rpc = getrpcbynumber(head->pml_map.pm_prog);
			if (rpc) {
				printf("  %s\n", rpc->r_name);
			} else {
				printf("\n");
			}
		}
	}
}

static void
get_inet_address(struct sockaddr_in *addr, char *host)
{
	struct addrinfo hints, *res;
	int error;

	(void) memset((char *)addr, 0, sizeof (*addr));
	addr->sin_addr.s_addr = inet_addr(host);
	if (addr->sin_addr.s_addr == -1 || addr->sin_addr.s_addr == 0) {
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_INET;
		if ((error = getaddrinfo(host, servname,
					 &hints, &res)) != 0) {
			errx(1, "%s: %s", host, gai_strerror(error));
		} else {
			memcpy(addr, res->ai_addr, res->ai_addrlen);
			freeaddrinfo(res);
		}
	} else {
		addr->sin_family = AF_INET;
	}
}

/*
 * reply_proc collects replies from the broadcast.
 * to get a unique list of responses the output of rpcinfo should
 * be piped through sort(1) and then uniq(1).
 */
#if 0
/*ARGSUSED*/
static bool_t
reply_proc(void *res, arpc_addr_t *who, ar_netid_t *nconf)
	/* void *res;			Nothing comes back */
	/* arpc_addr_t *who;		Who sent us the reply */
	/* ar_netid_t *nconf; 	On which transport the reply came */
{
	char *uaddr;
	char hostbuf[NI_MAXHOST];
	char *hostname;
	struct sockaddr *sa = (struct sockaddr *)who->buf;

	if (getnameinfo(sa, sa->sa_len, hostbuf, NI_MAXHOST, NULL, 0, 0)) {
		hostname = UNKNOWN;
	} else {
		hostname = hostbuf;
	}
	if (!(uaddr = taddr2uaddr(nconf, who))) {
		uaddr = UNKNOWN;
	}
	printf("%s\t%s\n", uaddr, hostname);
	if (strcmp(uaddr, UNKNOWN))
		free((char *)uaddr);
	return (FALSE);
}
#endif


static void
brdcst(ar_ioctx_t ioctx, int argc, char **argv)
{
#if 0
	enum clnt_stat rpc_stat;
	u_long prognum, vers;
#endif

	if (argc != 2)
		usage();

	fprintf(stderr, "broadcast not currently supported\n");
	exit(1);

#if 0
	prognum = getprognum(argv[0]);
	vers = getvers(argv[1]);
	rpc_stat = rpc_broadcast(prognum, vers, NULLPROC,
		(xdrproc_t) xdr_void, (char *)NULL, (xdrproc_t) xdr_void,
		(char *)NULL, (resultproc_t) reply_proc, NULL);
	if ((rpc_stat != RPC_SUCCESS) && (rpc_stat != RPC_TIMEDOUT))
		errx(1, "broadcast failed: %s", clnt_sperrno(rpc_stat));
	exit(0);
#endif
}

static bool_t
add_version(struct rpcbdump_short *rs, u_long vers)
{
	struct verslist *vl;

	for (vl = rs->vlist; vl; vl = vl->next)
		if (vl->vers == vers)
			break;
	if (vl)
		return (TRUE);
	vl = (struct verslist *)malloc(sizeof (struct verslist));
	if (vl == NULL)
		return (FALSE);
	vl->vers = vers;
	vl->next = rs->vlist;
	rs->vlist = vl;
	return (TRUE);
}

static bool_t
add_netid(struct rpcbdump_short *rs, char *netid)
{
	struct netidlist *nl;

	for (nl = rs->nlist; nl; nl = nl->next)
		if (strcmp(nl->netid, netid) == 0)
			break;
	if (nl)
		return (TRUE);
	nl = (struct netidlist *)malloc(sizeof (struct netidlist));
	if (nl == NULL)
		return (FALSE);
	nl->netid = netid;
	nl->next = rs->nlist;
	rs->nlist = nl;
	return (TRUE);
}

static void
rpcbdump(ar_ioctx_t ioctx, int dumptype, char *netid, int argc, char **argv)
{
	rpcblist_ptr head = NULL;
	struct timespec minutetimeout;
	register ar_client_t *client;
	struct rpcent *rpc;
	char *host;
	char *errstr;
	struct netidlist *nl;
	struct verslist *vl;
	struct rpcbdump_short *rs, *rs_tail;
	char buf[256];
	ar_stat_t clnt_st;
	arpc_createerr_t cerr;
	arpc_err_t err;
	struct rpcbdump_short *rs_head = NULL;
	

	minutetimeout.tv_sec = 60;
	minutetimeout.tv_nsec = 0;

	if (argc > 1) {
		usage();
	}
	if (argc == 1) {
		host = argv[0];
		if (netid == NULL) {
			client = clnt_rpcbind_create(ioctx, host, 
						     RPCBVERS, NULL, NULL);
		} else {
			client = getclnthandle(ioctx, host, netid,
					       RPCBVERS, NULL);
			if (cerr.cf_stat != ARPC_SUCCESS) {
				errstr = ar_astrcreateerror(&cerr);
				fprintf(stderr, "create clnt failed: %s\n", 
					errstr != NULL ? errstr : "<unknown>");
				if (errstr) {
					free(errstr);
				}
			}
		}
	} else {
		client = local_rpcb(ioctx, PMAPPROG, RPCBVERS);
	}

	if (client == (ar_client_t *)NULL) {
		fprintf(stderr, "rpcinfo: can't contact rpcbind\n");
		exit(1);
	}

	clnt_st = ar_clnt_call(client, RPCBPROC_DUMP, (axdrproc_t)axdr_void,
			       NULL, (axdrproc_t)axdr_rpcblist_ptr, 
			       (char *)&head, sizeof(head), 
			       &minutetimeout, &err);
	if (((clnt_st == ARPC_PROGVERSMISMATCH) ||
	     (clnt_st == ARPC_PROGUNAVAIL)) && 
	    (err.re_vers.low == RPCBVERS4)) {
		arpcvers_t vers;
		vers = RPCBVERS4;
		ar_clnt_control(client, AR_CLSET_VERS, (char *)&vers);
		clnt_st = ar_clnt_call(client, RPCBPROC_DUMP, 
				       (axdrproc_t)axdr_void,
				       NULL, (axdrproc_t)axdr_rpcblist_ptr, 
				       (char *)&head, sizeof(head), 
				       &minutetimeout, &err);
	}
	if (((clnt_st == ARPC_PROGVERSMISMATCH) ||
	     (clnt_st == ARPC_PROGUNAVAIL)) && 
	    (err.re_vers.high == PMAPVERS)) {
		arpcvers_t vers;
		int high, low;
		ar_pmaplist_t *pmaphead = NULL;
		rpcblist_ptr list, prev;

		vers = PMAPVERS;
		ar_clnt_control(client, AR_CLSET_VERS, (char *)&vers);
		clnt_st = ar_clnt_call(client, AR_PMAPPROC_DUMP,
				       (axdrproc_t)axdr_void,
				       NULL, (axdrproc_t)axdr_ar_pmaplist_ptr,
				       (char *)&pmaphead, sizeof(pmaphead),
				       &minutetimeout, &err);
		if (clnt_st != ARPC_SUCCESS) {
			goto failed;
		}
		/*
		 * convert to rpcblist_ptr format
		 */
		for (head = NULL; pmaphead != NULL;
		     pmaphead = pmaphead->pml_next) {
			list = (rpcblist *)malloc(sizeof (rpcblist));
			if (list == NULL) {
				goto error;
			}
			if (head == NULL) {
				head = list;
			} else {
				prev->rpcb_next = (rpcblist_ptr) list;
			}

			list->rpcb_next = NULL;
			list->rpcb_map.r_prog = pmaphead->pml_map.pm_prog;
			list->rpcb_map.r_vers = pmaphead->pml_map.pm_vers;
			if (pmaphead->pml_map.pm_prot == IPPROTO_UDP) {
				list->rpcb_map.r_netid = "udp";
			} else if (pmaphead->pml_map.pm_prot == IPPROTO_TCP) {
				list->rpcb_map.r_netid = "tcp";
			} else {
#define	MAXLONG_AS_STRING	"2147483648"
				list->rpcb_map.r_netid =
					malloc(strlen(MAXLONG_AS_STRING) + 1);
				if (list->rpcb_map.r_netid == NULL) {
					goto error;
				}
				sprintf(list->rpcb_map.r_netid, "%6ld",
					pmaphead->pml_map.pm_prot);
			}
			list->rpcb_map.r_owner = UNKNOWN;
			low = pmaphead->pml_map.pm_port & 0xff;
			high = (pmaphead->pml_map.pm_port >> 8) & 0xff;
			list->rpcb_map.r_addr = strdup("0.0.0.0.XXX.XXX");
			sprintf(&list->rpcb_map.r_addr[8], "%d.%d",
				high, low);
			prev = list;
		}
	}
	if (clnt_st != ARPC_SUCCESS) {
failed:
		errstr = ar_astrerror(&err);
		fprintf(stderr, "rpcinfo: can't contact rpcbind: %s\n", 
			errstr != NULL ? errstr : "<unknown>");
		if (errstr) {
			free(errstr);
		}
		exit(1);
	}

	if (head == NULL) {
		printf("No remote programs registered.\n");
	} else if (dumptype == RPCBDUMP) {
		printf(
"   program version netid     address                service    owner\n");
		for (; head != NULL; head = head->rpcb_next) {
			printf("%10u%5u    ",
				head->rpcb_map.r_prog, head->rpcb_map.r_vers);
			printf("%-9s ", head->rpcb_map.r_netid);
			printf("%-22s", head->rpcb_map.r_addr);
			rpc = getrpcbynumber(head->rpcb_map.r_prog);
			if (rpc) {
				printf(" %-10s", rpc->r_name);
			} else {
				printf(" %-10s", "-");
			}
			printf(" %s\n", head->rpcb_map.r_owner);
		}
	} else if (dumptype == RPCBDUMP_SHORT) {
		for (; head != NULL; head = head->rpcb_next) {
			for (rs = rs_head; rs; rs = rs->next) {
				if (head->rpcb_map.r_prog == rs->prog) {
					break;
				}
			}
			if (rs == NULL) {
				rs = (struct rpcbdump_short *)
					malloc(sizeof (struct rpcbdump_short));
				if (rs == NULL)
					goto error;
				rs->next = NULL;
				if (rs_head == NULL) {
					rs_head = rs;
					rs_tail = rs;
				} else {
					rs_tail->next = rs;
					rs_tail = rs;
				}
				rs->prog = head->rpcb_map.r_prog;
				rs->owner = head->rpcb_map.r_owner;
				rs->nlist = NULL;
				rs->vlist = NULL;
			}
			if (add_version(rs, head->rpcb_map.r_vers) == FALSE) {
				goto error;
			}
			if (add_netid(rs, head->rpcb_map.r_netid) == FALSE) {
				goto error;
			}
		}
		printf(
"   program version(s) netid(s)                         service     owner\n");
		for (rs = rs_head; rs; rs = rs->next) {
			char *p = buf;

			printf("%10ld  ", rs->prog);
			for (vl = rs->vlist; vl; vl = vl->next) {
				sprintf(p, "%d", vl->vers);
				p = p + strlen(p);
				if (vl->next) {
					sprintf(p++, ",");
				}
			}
			printf("%-10s", buf);
			buf[0] = '\0';
			for (nl = rs->nlist; nl; nl = nl->next) {
				strcat(buf, nl->netid);
				if (nl->next) {
					strcat(buf, ",");
				}
			}
			printf("%-32s", buf);
			rpc = getrpcbynumber(rs->prog);
			if (rpc) {
				printf(" %-11s", rpc->r_name);
			} else {
				printf(" %-11s", "-");
			}
			printf(" %s\n", rs->owner);
		}
	}
	ar_clnt_destroy(client);
	return;
error:	warnx("no memory");
	return;
}

static char nullstring[] = "\000";

static void
rpcbaddrlist(ar_ioctx_t ioctx, char *netid, int argc, char **argv)
{
	rpcb_entry_list_ptr head = NULL;
	struct timespec minutetimeout;
	register ar_client_t *client;
	struct rpcent *rpc;
	ar_stat_t clnt_stat;
	char *errstr;
	arpc_err_t err;
	char *host;
	RPCB parms;
	arpc_addr_t *targaddr;
	int rc;

	if (argc != 3)
		usage();
	host = argv[0];
	if (netid == NULL) {
		client = clnt_rpcbind_create(ioctx, host, 
					     RPCBVERS4, &targaddr, &netid);
	} else {
		client = getclnthandle(ioctx, host, netid,
				       RPCBVERS4, &targaddr);
	}
	if (client == (ar_client_t *)NULL) {
		fprintf(stderr, "rpcinfo: can't contact rpcbind\n");
		exit(1);
	}
	minutetimeout.tv_sec = 60;
	minutetimeout.tv_nsec = 0;

	parms.r_prog = 	getprognum(argv[1]);
	parms.r_vers = 	getvers(argv[2]);
	parms.r_netid = netid;
	if (targaddr == NULL) {
		parms.r_addr = nullstring;	/* for XDRing */
	} else {
		/*
		 * We also send the remote system the address we
		 * used to contact it in case it can help it
		 * connect back with us
		 */
		rc = ar_taddr2uaddr(ioctx, netid, targaddr, &parms.r_addr);
		if (rc != 0) {
			parms.r_addr = nullstring;
		}
		free(targaddr->buf);
		free(targaddr);
	}
	parms.r_owner = nullstring;

	clnt_stat = ar_clnt_call(client, RPCBPROC_GETADDRLIST, 
				 (axdrproc_t)axdr_rpcb, (char *)&parms, 
				 (axdrproc_t)axdr_rpcb_entry_list_ptr,
				 (char *)&head, sizeof(head), &minutetimeout,
				 &err);
	if (clnt_stat != ARPC_SUCCESS) {
		errstr = ar_astrerror(&err);
		fprintf(stderr, "rpcinfo: can't contact rpcbind: %s\n", 
			errstr != NULL ? errstr : "<unknown>");
		if (errstr) {
			free(errstr);
		}
		ar_clnt_destroy(client);
		exit(1);
	}
	if (head == NULL) {
		printf("No remote programs registered.\n");
	} else {
		printf(
	"   program vers  tp_family/name/class    address\t\t  service\n");
		for (; head != NULL; head = head->rpcb_entry_next) {
			rpcb_entry *re;
			char buf[128];

			re = &head->rpcb_entry_map;
			printf("%10u%3u    ",
				parms.r_prog, parms.r_vers);
			sprintf(buf, "%s/%s/%s ",
				re->r_nc_protofmly, re->r_nc_proto,
				re->r_nc_semantics == AR_SEM_CLTS ? "clts" :
				re->r_nc_semantics == AR_SEM_COTS ? "cots" :
						"cots_ord");
			printf("%-24s", buf);
			printf("%-24s", re->r_maddr);
			rpc = getrpcbynumber(parms.r_prog);
			if (rpc) {
				printf(" %-13s", rpc->r_name);
			} else {
				printf(" %-13s", "-");
			}
			printf("\n");
		}
	}
	ar_clnt_destroy(client);
	return;
}

/*
 * monitor rpcbind
 */
static void
rpcbgetstat(ar_ioctx_t ioctx, int argc, char **argv)
{
	rpcb_stat_byvers inf;
	struct timespec minutetimeout;
	register ar_client_t *client;
	char *host;
	int i, j;
	rpcbs_addrlist *pa;
	rpcbs_rmtcalllist *pr;
	ar_stat_t clnt_stat;
	arpc_err_t err;
	char *errstr;
	int cnt, flen;
#define	MAXFIELD	64
	char fieldbuf[MAXFIELD];
#define	MAXLINE		256
	char linebuf[MAXLINE];
	char *cp, *lp;
	char *pmaphdr[] = {
		"NULL", "SET", "UNSET", "GETPORT",
		"DUMP", "CALLIT"
	};
	char *rpcb3hdr[] = {
		"NULL", "SET", "UNSET", "GETADDR", "DUMP", "CALLIT", "TIME",
		"U2T", "T2U"
	};
	char *rpcb4hdr[] = {
		"NULL", "SET", "UNSET", "GETADDR", "DUMP", "CALLIT", "TIME",
		"U2T",  "T2U", "VERADDR", "INDRECT", "GETLIST", "GETSTAT"
	};

#define	TABSTOP	8

	if (argc >= 1) {
		host = argv[0];
		client = clnt_rpcbind_create(ioctx, host, RPCBVERS4, 
					     NULL, NULL);
	} else {
		client = local_rpcb(ioctx, PMAPPROG, RPCBVERS4);
	}
	if (client == (ar_client_t *)NULL) {
		fprintf(stderr, "rpcinfo: can't contact rpcbind\n");
		exit(1);
	}
	minutetimeout.tv_sec = 60;
	minutetimeout.tv_nsec = 0;
	memset((char *)&inf, 0, sizeof (rpcb_stat_byvers));
	clnt_stat = ar_clnt_call(client, RPCBPROC_GETSTAT, 
				 (axdrproc_t)axdr_void, NULL,
				 (axdrproc_t)axdr_rpcb_stat_byvers, 
				 (char *)&inf, sizeof(inf), &minutetimeout, 
				 &err);
	if (clnt_stat != ARPC_SUCCESS) {
		errstr = ar_astrerror(&err);
		fprintf(stderr, "rpcinfo: can't contact rpcbind: %s\n", 
			errstr);
		if (errstr) {
			free(errstr);
		}
		exit(1);
	}

	printf("PORTMAP (version 2) statistics\n");
	lp = linebuf;
	for (i = 0; i <= rpcb_highproc_2; i++) {
		fieldbuf[0] = '\0';
		switch (i) {
		case AR_PMAPPROC_SET:
			sprintf(fieldbuf, "%d/", inf[RPCBVERS_2_STAT].setinfo);
			break;
		case AR_PMAPPROC_UNSET:
			sprintf(fieldbuf, "%d/",
				inf[RPCBVERS_2_STAT].unsetinfo);
			break;
		case AR_PMAPPROC_GETPORT:
			cnt = 0;
			for (pa = inf[RPCBVERS_2_STAT].addrinfo; pa;
			     pa = pa->next) {
				cnt += pa->success;
			}
			sprintf(fieldbuf, "%d/", cnt);
			break;
		case AR_PMAPPROC_CALLIT:
			cnt = 0;
			for (pr = inf[RPCBVERS_2_STAT].rmtinfo; pr;
			     pr = pr->next) {
				cnt += pr->success;
			}
			sprintf(fieldbuf, "%d/", cnt);
			break;
		default: 
			break;  /* For the remaining ones */
		}
		cp = &fieldbuf[0] + strlen(fieldbuf);
		sprintf(cp, "%d", inf[RPCBVERS_2_STAT].info[i]);
		flen = strlen(fieldbuf);
		printf("%s%s", pmaphdr[i],
			spaces((TABSTOP * (1 + flen / TABSTOP))
			- strlen(pmaphdr[i])));
		sprintf(lp, "%s%s", fieldbuf,
			spaces(cnt = ((TABSTOP * (1 + flen / TABSTOP))
			- flen)));
		lp += (flen + cnt);
	}
	printf("\n%s\n\n", linebuf);

	if (inf[RPCBVERS_2_STAT].info[AR_PMAPPROC_CALLIT]) {
		printf("PMAP_RMTCALL call statistics\n");
		print_rmtcallstat(RPCBVERS_2_STAT, &inf[RPCBVERS_2_STAT]);
		printf("\n");
	}

	if (inf[RPCBVERS_2_STAT].info[AR_PMAPPROC_GETPORT]) {
		printf("PMAP_GETPORT call statistics\n");
		print_getaddrstat(RPCBVERS_2_STAT, &inf[RPCBVERS_2_STAT]);
		printf("\n");
	}

	printf("RPCBIND (version 3) statistics\n");
	lp = linebuf;
	for (i = 0; i <= rpcb_highproc_3; i++) {
		fieldbuf[0] = '\0';
		switch (i) {
		case RPCBPROC_SET:
			sprintf(fieldbuf, "%d/", inf[RPCBVERS_3_STAT].setinfo);
			break;
		case RPCBPROC_UNSET:
			sprintf(fieldbuf, "%d/",
				inf[RPCBVERS_3_STAT].unsetinfo);
			break;
		case RPCBPROC_GETADDR:
			cnt = 0;
			for (pa = inf[RPCBVERS_3_STAT].addrinfo; pa;
				pa = pa->next)
				cnt += pa->success;
			sprintf(fieldbuf, "%d/", cnt);
			break;
		case RPCBPROC_CALLIT:
			cnt = 0;
			for (pr = inf[RPCBVERS_3_STAT].rmtinfo; pr;
				pr = pr->next)
				cnt += pr->success;
			sprintf(fieldbuf, "%d/", cnt);
			break;
		default:
			break;  /* For the remaining ones */
		}
		cp = &fieldbuf[0] + strlen(fieldbuf);
		sprintf(cp, "%d", inf[RPCBVERS_3_STAT].info[i]);
		flen = strlen(fieldbuf);
		printf("%s%s", rpcb3hdr[i],
			spaces((TABSTOP * (1 + flen / TABSTOP))
			- strlen(rpcb3hdr[i])));
		sprintf(lp, "%s%s", fieldbuf,
			spaces(cnt = ((TABSTOP * (1 + flen / TABSTOP))
			- flen)));
		lp += (flen + cnt);
	}
	printf("\n%s\n\n", linebuf);

	if (inf[RPCBVERS_3_STAT].info[RPCBPROC_CALLIT]) {
		printf("RPCB_RMTCALL (version 3) call statistics\n");
		print_rmtcallstat(RPCBVERS_3_STAT, &inf[RPCBVERS_3_STAT]);
		printf("\n");
	}

	if (inf[RPCBVERS_3_STAT].info[RPCBPROC_GETADDR]) {
		printf("RPCB_GETADDR (version 3) call statistics\n");
		print_getaddrstat(RPCBVERS_3_STAT, &inf[RPCBVERS_3_STAT]);
		printf("\n");
	}

	printf("RPCBIND (version 4) statistics\n");

	for (j = 0; j <= 9; j += 9) { /* Just two iterations for printing */
		lp = linebuf;
		for (i = j; i <= MAX(8, rpcb_highproc_4 - 9 + j); i++) {
			fieldbuf[0] = '\0';
			switch (i) {
			case RPCBPROC_SET:
				sprintf(fieldbuf, "%d/",
					inf[RPCBVERS_4_STAT].setinfo);
				break;
			case RPCBPROC_UNSET:
				sprintf(fieldbuf, "%d/",
					inf[RPCBVERS_4_STAT].unsetinfo);
				break;
			case RPCBPROC_GETADDR:
				cnt = 0;
				for (pa = inf[RPCBVERS_4_STAT].addrinfo; pa;
					pa = pa->next)
					cnt += pa->success;
				sprintf(fieldbuf, "%d/", cnt);
				break;
			case RPCBPROC_CALLIT:
				cnt = 0;
				for (pr = inf[RPCBVERS_4_STAT].rmtinfo; pr;
					pr = pr->next)
					cnt += pr->success;
				sprintf(fieldbuf, "%d/", cnt);
				break;
			default: break;  /* For the remaining ones */
			}
			cp = &fieldbuf[0] + strlen(fieldbuf);
			/*
			 * XXX: We also add RPCBPROC_GETADDRLIST queries to
			 * RPCB_GETADDR because rpcbind includes the
			 * RPCB_GETADDRLIST successes in RPCB_GETADDR.
			 */
			if (i != RPCBPROC_GETADDR)
			    sprintf(cp, "%d", inf[RPCBVERS_4_STAT].info[i]);
			else
			    sprintf(cp, "%d", inf[RPCBVERS_4_STAT].info[i] +
			    inf[RPCBVERS_4_STAT].info[RPCBPROC_GETADDRLIST]);
			flen = strlen(fieldbuf);
			printf("%s%s", rpcb4hdr[i],
				spaces((TABSTOP * (1 + flen / TABSTOP))
				- strlen(rpcb4hdr[i])));
			sprintf(lp, "%s%s", fieldbuf,
				spaces(cnt = ((TABSTOP * (1 + flen / TABSTOP))
				- flen)));
			lp += (flen + cnt);
		}
		printf("\n%s\n", linebuf);
	}

	if (inf[RPCBVERS_4_STAT].info[RPCBPROC_CALLIT] ||
			    inf[RPCBVERS_4_STAT].info[RPCBPROC_INDIRECT]) {
		printf("\n");
		printf("RPCB_RMTCALL (version 4) call statistics\n");
		print_rmtcallstat(RPCBVERS_4_STAT, &inf[RPCBVERS_4_STAT]);
	}

	if (inf[RPCBVERS_4_STAT].info[RPCBPROC_GETADDR]) {
		printf("\n");
		printf("RPCB_GETADDR (version 4) call statistics\n");
		print_getaddrstat(RPCBVERS_4_STAT, &inf[RPCBVERS_4_STAT]);
	}
	ar_clnt_destroy(client);
}

/*
 * Delete registeration for this (prog, vers, netid)
 */
static void
deletereg(char *netid, int argc, char **argv)
{
#if 0
	ar_netid_t *nconf = NULL;
#endif
	if (argc != 2)
		usage();
#if 0
	if ((rpcb_unset(getprognum(argv[0]), getvers(argv[1]), nconf)) == 0)
		errx(1,
	"could not delete registration for prog %s version %s",
			argv[0], argv[1]);
#endif
}

/*
 * Create and return a handle for the given nconf.
 * Exit if cannot create handle.
 */
static ar_client_t *
clnt_addr_create(ar_ioctx_t ioctx, char *address, const char *netid,
		 u_long prog, u_long vers)
{
	ar_client_t *client;
	arpc_addr_t *nbuf;
	ar_clnt_attr_t attr;
	arpc_createerr_t cerr;
	char *errstr;
	int err;

	client = NULL;

	err = ar_uaddr2taddr(ioctx, netid, address, &nbuf);
	if (err != 0) {
		fprintf(stderr, "no address for client handle (%s %s): %s",
			netid, address, strerror(err));
		exit(1);
		return NULL;
	}

	err = ar_clnt_attr_init(&attr);
	if (err != 0) {
		goto cleanup;
	}

	err = ar_clnt_attr_set_conncb(&attr, &clnt_com_create_cb, NULL);
	if (err != 0) {
		ar_clnt_attr_destroy(&attr);
		goto cleanup;
	}

	err = ar_clnt_tli_create(ioctx, netid, nbuf, prog, vers, &attr, 
				 &cerr, &client);
	ar_clnt_attr_destroy(&attr);
	if (err != 0) {
		errstr = ar_astrcreateerror(&cerr);
		fprintf(stderr, "create client conn: %s\n", errstr != NULL ? 
			errstr : "<unknown>");
		if (errstr) {
			free(errstr);
		}
		errstr = NULL;
		goto cleanup;
	}

cleanup:
	if (nbuf->buf) {
		free(nbuf->buf);
	}
	free(nbuf);
	if (client == NULL) {
		exit(1);
	}
	return (client);
}

/*
 * If the version number is given, ping that (prog, vers); else try to find
 * the version numbers supported for that prog and ping all the versions.
 * Remote rpcbind is not contacted for this service. The requests are
 * sent directly to the services themselves.
 */
static void
addrping(ar_ioctx_t ioctx, char *address, char *netid, int argc, char **argv)
{
	ar_client_t *client;
	struct timespec to;
	ar_stat_t rpc_stat;
	u_long prognum, versnum, minvers, maxvers;
	arpc_err_t rpcerr;
	int failure = 0;

	if (argc < 1 || argc > 2 || (netid == NULL)) {
		usage();
	}
	to.tv_sec = 10;
	to.tv_nsec = 0;
	prognum = getprognum(argv[0]);
	if (argc == 1) {	/* Version number not known */
		/*
		 * A call to version 0 should fail with a program/version
		 * mismatch, and give us the range of versions supported.
		 */
		versnum = MIN_VERS;
	} else {
		versnum = getvers(argv[1]);
	}


	client = clnt_addr_create(ioctx, address, netid, prognum, versnum);

	

	rpc_stat = ar_clnt_call(client, AR_NULLPROC, (axdrproc_t)axdr_void,
				(char *)NULL, (axdrproc_t)axdr_void,
				(char *)NULL, 0, &to, &rpcerr);
	ar_clnt_destroy(client);
	if (argc == 2) {
		/* Version number was known */
		if (pstatus(ioctx, prognum, versnum, &rpcerr) < 0) {
			failure = 1;
		}
		if (failure) {
			exit(1);
		}
		return;
	}
	/* Version number not known */
	if (rpc_stat != ARPC_PROGVERSMISMATCH) {
		if (rpcerr.re_status == ARPC_SUCCESS) {
			fprintf(stderr, "expected prog version mismatch "
				"on vers 0..\n");
		} else {
			pstatus(ioctx, prognum, versnum, &rpcerr);
		}			
		exit(1);
		return;
	}


	minvers = rpcerr.re_vers.low;
	maxvers = rpcerr.re_vers.high;

	for (versnum = minvers; versnum <= maxvers; versnum++) {
		client = clnt_addr_create(ioctx, address, netid,
					  prognum, versnum);
		rpc_stat = ar_clnt_call(client, AR_NULLPROC, 
					(axdrproc_t)axdr_void, (char *)NULL, 
					(axdrproc_t)axdr_void, (char *)NULL, 
					0, &to, &rpcerr);
		ar_clnt_destroy(client);
		if (pstatus(ioctx, prognum, versnum, &rpcerr) < 0) {
			failure = 1;
		}
	}
	if (failure) {
		exit(1);
	}
	return;
}

/*
 * If the version number is given, ping that (prog, vers); else try to find
 * the version numbers supported for that prog and ping all the versions.
 * Remote rpcbind is *contacted* for this service. The requests are
 * then sent directly to the services themselves.
 */
static void
progping(ar_ioctx_t ioctx, char *netid, int argc, char **argv)
{
	ar_client_t *client;
	struct timespec to;
	ar_stat_t rpc_stat;
	u_long prognum, versnum, minvers, maxvers;
	arpc_err_t rpcerr;
	int failure = 0;
	ar_clnt_attr_t attr;
	arpc_createerr_t cerr;
	char *errstr;
	int err;

	if (argc < 2 || argc > 3 || (netid == NULL))
		usage();
	prognum = getprognum(argv[1]);
	if (argc == 2) { /* Version number not known */
		/*
		 * A call to version 0 should fail with a program/version
		 * mismatch, and give us the range of versions supported.
		 */
		versnum = MIN_VERS;
	} else {
		versnum = getvers(argv[2]);
	}

	err = ar_clnt_attr_init(&attr);
	if (err != 0) {
		return;
	}
	
	err = ar_clnt_attr_set_conncb(&attr, &clnt_com_create_cb, NULL);
	if (err != 0) {
		ar_clnt_attr_destroy(&attr);
		return;
	}

	err = ar_clnt_create(ioctx, argv[0], prognum, versnum, netid, 
			     &attr, &cerr, &client);
	ar_clnt_attr_destroy(&attr);
	if (err != 0) {
		errstr = ar_astrcreateerror(&cerr);
		fprintf(stderr, "program %lu version %lu is not "
			"available: %s\n", prognum, versnum, 
			errstr != NULL ? errstr : "<unknown>");
		if (errstr) {
			free(errstr);
		}
		exit(1);
		return;
	}
		
	to.tv_sec = 10;
	to.tv_nsec = 0;

	
	rpc_stat = ar_clnt_call(client, AR_NULLPROC,
				(axdrproc_t)axdr_void, NULL,
				(axdrproc_t)axdr_void, NULL, 0, &to, &rpcerr);
	if (argc == 3) {
		ar_clnt_destroy(client);
		/* Version number was known */
		if (pstatus(ioctx, prognum, versnum, &rpcerr) < 0) {
			failure = 1;
		}
		if (failure) {
			exit(1);
		}
		return;
	}
	/* Version number not known */
	if (rpc_stat != ARPC_PROGVERSMISMATCH) {
		ar_clnt_destroy(client);
		if (rpcerr.re_status == ARPC_SUCCESS) {
			fprintf(stderr, "expected prog version mismatch "
				"on vers 0..\n");
		} else {
			pstatus(ioctx, prognum, versnum, &rpcerr);
		}			
		exit(1);
		return;
	}		

	minvers = rpcerr.re_vers.low;
	maxvers = rpcerr.re_vers.high;

	for (versnum = minvers; versnum <= maxvers; versnum++) {
		ar_clnt_control(client, AR_CLSET_VERS, (char *)&versnum);

		rpc_stat = ar_clnt_call(client, AR_NULLPROC,
					(axdrproc_t)axdr_void, NULL,
					(axdrproc_t)axdr_void, NULL, 0, 
					&to, &rpcerr);
		if (pstatus(ioctx, prognum, versnum, &rpcerr) < 0) {
			failure = 1;
		}
	}
	ar_clnt_destroy(client);
	if (failure) {
		exit(1);
	}
	return;
}

static void
usage()
{
	fprintf(stderr, "usage: rpcinfo [-m | -s] [host]\n");
	fprintf(stderr, "       rpcinfo -p [host]\n");
	fprintf(stderr, "       rpcinfo -T netid host prognum [versnum]\n");
	fprintf(stderr, "       rpcinfo -l host prognum versnum\n");
	fprintf(stderr,
"       rpcinfo [-n portnum] -u | -t host prognum [versnum]\n");
	fprintf(stderr,
"       rpcinfo -a serv_address -T netid prognum [version]\n");
	fprintf(stderr, "       rpcinfo -b prognum versnum\n");
	fprintf(stderr, "       rpcinfo -d [-T netid] prognum versnum\n");
	exit(1);
}

static u_long
getprognum (char *arg)
{
	char *strptr;
	register struct rpcent *rpc;
	register u_long prognum;
	char *tptr = arg;

	while (*tptr && isdigit(*tptr++));
	if (*tptr || isalpha(*(tptr - 1))) {
		rpc = getrpcbyname(arg);
		if (rpc == NULL)
			errx(1, "%s is unknown service", arg);
		prognum = rpc->r_number;
	} else {
		prognum = strtol(arg, &strptr, 10);
		if (strptr == arg || *strptr != '\0')
			errx(1, "%s is illegal program number", arg);
	}
	return (prognum);
}

static u_long
getvers(char *arg)
{
	char *strptr;
	register u_long vers;

	vers = (int) strtol(arg, &strptr, 10);
	if (strptr == arg || *strptr != '\0')
		errx(1, "%s is illegal version number", arg);
	return (vers);
}

/*
 * This routine should take a pointer to an "rpc_err" structure, rather than
 * a pointer to a ar_client_t structure, but "clnt_perror" takes a pointer to
 * a ar_client_t structure rather than a pointer to an "rpc_err" structure.
 * As such, we have to keep the ar_client_t structure around in order to print
 * a good error message.
 */
static int
pstatus(ar_ioctx_t ioctx, u_long prog, u_long vers, const arpc_err_t *errp)
{
	char *errstr;

	if (errp->re_status != ARPC_SUCCESS) {
		errstr = ar_astrerror(errp);
		printf("program %lu version %lu is not available: %s\n",
		       prog, vers, errstr != NULL ? errstr : 
		       "<error missing>");
		if (errstr) {
			free(errstr);
		}
		return (-1);
	} else {
		printf("program %lu version %lu ready and waiting\n",
		       prog, vers);
		return (0);
	}
}

static ar_client_t *
clnt_rpcbind_create(ar_ioctx_t ioctx, char *host, int rpcbversnum, arpc_addr_t **targaddr, char **netidstr)
{
	int i;
	ar_netid_t *nconf;
	ar_client_t *clnt = NULL;
	int err;

	for (i = 0; ; i++) {
		err = ar_idx2netid(ioctx, i, &nconf);
		if (err != 0) {
			return NULL;
		}
		if (!nconf) {
			return NULL;
		}
		clnt = getclnthandle(ioctx, host, nconf->an_netid, 
				     rpcbversnum, targaddr);
		if (clnt) {
			*netidstr = (char *) nconf->an_netid;
			break;
		}
	}
	return (clnt);
}

static ar_client_t *
getclnthandle(ar_ioctx_t ioctx, char *host, const char *netid,
	      u_long rpcbversnum, arpc_addr_t **targaddr)
{
	arpc_addr_t addr;
	struct addrinfo hints, *res;
	ar_client_t *client = NULL;
	ar_clnt_attr_t attr;
	create_stat_t cstat;
	arpc_createerr_t cerr;
	char *errstr;
	int err;

	memset(&cstat, 0, sizeof(cstat));

	/* Get the address of the rpcbind */
	memset(&hints, 0, sizeof hints);
	if (getaddrinfo(host, servname, &hints, &res) != 0) {
		fprintf(stderr, "lookup hostname '%s' failed\n", host);
		return (NULL);
	}
	addr.len = addr.maxlen = res->ai_addrlen;
	addr.buf = (char *)res->ai_addr;

	err = ar_clnt_attr_init(&attr);
	if (err != 0) {
		return NULL;
	}

	err = ar_clnt_attr_set_conncb(&attr, &clnt_com_create_cb, &cstat);
	if (err != 0) {
		ar_clnt_attr_destroy(&attr);
		return NULL;
	}

	err = ar_clnt_tli_create(ioctx, netid, &addr, RPCBPROG,
				rpcbversnum, &attr, &cerr, &client);
	ar_clnt_attr_destroy(&attr);
	if (err != 0) {
		errstr = ar_astrcreateerror(&cerr);
		fprintf(stderr, "rpcbind connect failed: %s\n",
			errstr != NULL ? errstr : "<unknown>");
		if (errstr) {
			free(errstr);
		}
		freeaddrinfo(res);
		return NULL;
	}


	while (!cstat.done) {
		err = ar_ioctx_loop(ioctx);
		if (err != 0) {
			fprintf(stderr, "io wait loop failure: %s\n", 
				strerror(err));
			ar_clnt_destroy(client);
			freeaddrinfo(res);
			return NULL;
		}
	}

	if (cstat.cerr.cf_stat != ARPC_SUCCESS) {
		ar_clnt_destroy(client);
		freeaddrinfo(res);
		return NULL;
	}

	if (targaddr != NULL) {
		*targaddr = (arpc_addr_t *)malloc(sizeof (arpc_addr_t));
		if (*targaddr != NULL) {
			(*targaddr)->maxlen = addr.maxlen;
			(*targaddr)->len = addr.len;
			(*targaddr)->buf = (char *)malloc(addr.len);
			if ((*targaddr)->buf != NULL) {
				memcpy((*targaddr)->buf, addr.buf,
				       addr.len);
			}
		}
	}
	freeaddrinfo(res);
	return (client);
}

static void
print_rmtcallstat(int rtype, rpcb_stat *infp)
{
	register rpcbs_rmtcalllist_ptr pr;
	struct rpcent *rpc;

	if (rtype == RPCBVERS_4_STAT)
		printf(
		"prog\t\tvers\tproc\tnetid\tindirect success failure\n");
	else
		printf("prog\t\tvers\tproc\tnetid\tsuccess\tfailure\n");
	for (pr = infp->rmtinfo; pr; pr = pr->next) {
		rpc = getrpcbynumber(pr->prog);
		if (rpc)
			printf("%-16s", rpc->r_name);
		else
			printf("%-16d", pr->prog);
		printf("%d\t%d\t%s\t",
			pr->vers, pr->proc, pr->netid);
		if (rtype == RPCBVERS_4_STAT)
			printf("%d\t ", pr->indirect);
		printf("%d\t%d\n", pr->success, pr->failure);
	}
}

static void
print_getaddrstat(int rtype, rpcb_stat *infp)
{
	rpcbs_addrlist_ptr al;
	register struct rpcent *rpc;

	printf("prog\t\tvers\tnetid\t  success\tfailure\n");
	for (al = infp->addrinfo; al; al = al->next) {
		rpc = getrpcbynumber(al->prog);
		if (rpc)
			printf("%-16s", rpc->r_name);
		else
			printf("%-16d", al->prog);
		printf("%d\t%s\t  %-12d\t%d\n",
			al->vers, al->netid,
			al->success, al->failure);
	}
}

static char *
spaces(int howmany)
{
	static char space_array[] =		/* 64 spaces */
	"                                                                ";

	if (howmany <= 0 || howmany > sizeof (space_array)) {
		return ("");
	}
	return (&space_array[sizeof (space_array) - howmany - 1]);
}
