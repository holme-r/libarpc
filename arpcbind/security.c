/*	$NetBSD: security.c,v 1.5 2000/06/08 09:01:05 fvdl Exp $	*/
/*	$FreeBSD: src/usr.sbin/rpcbind/security.c,v 1.6 2002/12/16 22:24:26 mbr Exp $ */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libarpc/arpc.h>
#include "rpcb_prot.h"
#include "pmap_prot.h"
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <netdb.h>

#if 0
/*
 * XXX for special case checks in check_callit.
 * FIXME: these are not portable...
 */
#include <rpcsvc/mount.h>
#include <rpcsvc/rquota.h>
#include <rpcsvc/nfs_prot.h>
#include <rpcsvc/yp.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yppasswd.h>

#else

/*
 * Pulled special case values from Centos 5.0 host system files
 */
/* Pulled from rpcsvc/mount.h */
#define MOUNTPROG 100005
#define MOUNTPROC_MNT 1
#define MOUNTPROC_UMNT 3

/* Pulled from rpcsvc/yp.h */
#define YPBINDPROG 100007
#define YPBINDPROC_SETDOM 2

#define YPPROG 100004
#define YPPROC_ALL 8
#define YPPROC_MATCH 3
#define YPPROC_FIRST 4
#define YPPROC_NEXT 5

/* Pulled from rpcsvc/yppasswd.h */
#define YPPASSWDPROG 100009

/* Pulled from rpcsvc/nfs_prot.h */
#define NFS_PROGRAM 100003

/* Pulled from rpcsvc/rquota.h */
#define RQUOTAPROG 100011

/* Pulled from tcpd.h */
#define RQ_DAEMON        2               /* server process (argv[0]) */
#define RQ_CLIENT_SIN   6               /* client endpoint (internal) */

#endif

#include "rpcbind.h"

#ifdef HAVE_LIBWRAP
# include <tcpd.h>
#ifndef LIBWRAP_ALLOW_FACILITY
# define LIBWRAP_ALLOW_FACILITY LOG_AUTH
#endif
#ifndef LIBWRAP_ALLOW_SEVERITY
# define LIBWRAP_ALLOW_SEVERITY LOG_INFO
#endif
#ifndef LIBWRAP_DENY_FACILITY
# define LIBWRAP_DENY_FACILITY LOG_AUTH
#endif
#ifndef LIBWRAP_DENY_SEVERITY
# define LIBWRAP_DENY_SEVERITY LOG_WARNING
#endif
int allow_severity = LIBWRAP_ALLOW_FACILITY|LIBWRAP_ALLOW_SEVERITY;
int deny_severity = LIBWRAP_DENY_FACILITY|LIBWRAP_DENY_SEVERITY;
#endif

#ifndef PORTMAP_LOG_FACILITY
# define PORTMAP_LOG_FACILITY LOG_AUTH
#endif
#ifndef PORTMAP_LOG_SEVERITY
# define PORTMAP_LOG_SEVERITY LOG_INFO
#endif
int log_severity = PORTMAP_LOG_FACILITY|PORTMAP_LOG_SEVERITY;

extern int verboselog;

int 
check_access(ar_svc_req_t *rqstp, void *args, unsigned int rpcbvers)
{
	arpc_addr_t *caller;
	struct sockaddr *addr;
	ar_svc_xprt_t *xprt;
	arpcproc_t proc;
#ifdef HAVE_LIBWRAP
	struct request_info req;
#endif
	arpcprog_t prog = 0;
	rpcb *rpcbp;
	struct ar_pmap *pmap;
	bool_t ret;

	xprt = rqstp->rq_xprt;
	proc = rqstp->rq_proc;

	caller = ar_svc_getrpccaller(xprt);
	if (!caller) {
		return 0;
	}
	addr = (struct sockaddr *)caller->buf;

	/*
	 * The older PMAP_* equivalents have the same numbers, so
	 * they are accounted for here as well.
	 */
	switch (proc) {
	case RPCBPROC_GETADDR:
	case RPCBPROC_SET:
	case RPCBPROC_UNSET:
		if (rpcbvers > PMAPVERS) {
			rpcbp = (rpcb *)args;
			prog = rpcbp->r_prog;
		} else {
			pmap = (struct ar_pmap *)args;
			prog = pmap->pm_prog;
		}
		if (proc == RPCBPROC_GETADDR) {
			break;
		}
		if (!insecure && !is_loopback(caller)) {
			if (verboselog)
				logit(log_severity, addr, caller->len, 
				      proc, prog,
				      " declined (non-loopback sender)");
			ret = FALSE;
			goto done;
		}
		break;
	case RPCBPROC_CALLIT:
	case RPCBPROC_INDIRECT:
	case RPCBPROC_DUMP:
	case RPCBPROC_GETTIME:
	case RPCBPROC_UADDR2TADDR:
	case RPCBPROC_TADDR2UADDR:
	case RPCBPROC_GETVERSADDR:
	case RPCBPROC_GETADDRLIST:
	case RPCBPROC_GETSTAT:
	default:
		break;
	}

#ifdef HAVE_LIBWRAP
	if (addr->sa_family == AF_LOCAL) {
		ret = TRUE;
		goto done;
	}
	request_init(&req, RQ_DAEMON, "rpcbind", RQ_CLIENT_SIN, addr, 0);
	sock_methods(&req);
	if(!hosts_access(&req)) {
		logit(deny_severity, addr, caller->len, proc, prog, 
		      ": request from unauthorized host");
		ret = FALSE;
		goto done;
	}
#endif
	if (verboselog) {
		logit(log_severity, addr, caller->len, proc, prog, "");
	}
	ret = TRUE;
done:
	if (caller) {
		if (caller->buf) {
			free(caller->buf);
		}
		caller->buf = NULL;
		free(caller);
		caller = NULL;
	}
	return ret;
}

int
is_loopback(arpc_addr_t *nbuf)
{
	struct sockaddr *addr = (struct sockaddr *)nbuf->buf;
	struct sockaddr_in *sin;
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif

	switch (addr->sa_family) {
	case AF_INET:
		if (!oldstyle_local)
			return 0;
		sin = (struct sockaddr_in *)addr;
        	return ((sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) &&
		    (ntohs(sin->sin_port) < IPPORT_RESERVED));
#ifdef INET6
	case AF_INET6:
		if (!oldstyle_local)
			return 0;
		sin6 = (struct sockaddr_in6 *)addr;
		return (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) &&
		    (ntohs(sin6->sin6_port) < IPPORT_RESERVED));
#endif
	case AF_LOCAL:
		return 1;
	default:
		break;
	}
	
	return 0;
}


/* logit - report events of interest via the syslog daemon */
void
logit(int severity, struct sockaddr *addr, socklen_t alen,
      arpcproc_t procnum, arpcprog_t prognum,
      const char *text)
{
	const char *procname;
	char	procbuf[32];
	char   *progname;
	char	progbuf[32];
	char fromname[NI_MAXHOST];
	struct rpcent *rpc;
	static const char *procmap[] = {
	/* RPCBPROC_NULL */		"null",
	/* RPCBPROC_SET */		"set",
	/* RPCBPROC_UNSET */		"unset",
	/* RPCBPROC_GETADDR */		"getport/addr",
	/* RPCBPROC_DUMP */		"dump",
	/* RPCBPROC_CALLIT */		"callit",
	/* RPCBPROC_GETTIME */		"gettime",
	/* RPCBPROC_UADDR2TADDR */	"uaddr2taddr",
	/* RPCBPROC_TADDR2UADDR */	"taddr2uaddr",
	/* RPCBPROC_GETVERSADDR */	"getversaddr",
	/* RPCBPROC_INDIRECT */		"indirect",
	/* RPCBPROC_GETADDRLIST */	"getaddrlist",
	/* RPCBPROC_GETSTAT */		"getstat"
	};
   
	/*
	 * Fork off a process or the portmap daemon might hang while
	 * getrpcbynumber() or syslog() does its thing.
	 */

	if (fork() == 0) {
		/* Try to map program number to name. */

		if (prognum == 0) {
			progname = "";
		} else if ((rpc = getrpcbynumber((int) prognum))) {
			progname = rpc->r_name;
		} else {
			snprintf(progname = progbuf, sizeof(progbuf), "%u",
			    (unsigned)prognum);
		}

		/* Try to map procedure number to name. */

		if (procnum >= (sizeof procmap / sizeof (char *))) {
			snprintf(procbuf, sizeof procbuf, "%u",
			    (unsigned)procnum);
			procname = procbuf;
		} else
			procname = procmap[procnum];

		/* Write syslog record. */

		if (addr->sa_family == AF_LOCAL)
			strcpy(fromname, "local");
		else
			getnameinfo(addr, alen, fromname,
			    sizeof fromname, NULL, 0, NI_NUMERICHOST);

		syslog(severity, "connect from %s to %s(%s)%s",
			fromname, procname, progname, text);
		_exit(0);
	}
}

int
check_callit(ar_svc_req_t *rqstp, rpcb_rmtcallargs *args, int versnum)
{
	arpc_addr_t *caller;
	struct sockaddr *sa;
	socklen_t slen;
	bool_t ret;

	caller = ar_svc_getrpccaller(rqstp->rq_xprt);
	if (!caller) {
		return 0;
	}
	slen = caller->len;
	sa = (struct sockaddr *)caller->buf;
	
	/*
	 * Always allow calling NULLPROC
	 */
	if (args->proc == 0) {
		ret = TRUE;
		goto done;
	}

	/*
	 * XXX - this special casing sucks.
	 */
	switch (args->prog) {
	case RPCBPROG:
		/*
		 * Allow indirect calls to ourselves in insecure mode.
		 * The is_loopback checks aren't useful then anyway.
		 */
		if (!insecure) {
			ret = FALSE;
			goto done;
		}
		break;
	case MOUNTPROG:
		if (args->proc != MOUNTPROC_MNT && 
		    args->proc != MOUNTPROC_UMNT) {
			break;
		}
		ret = FALSE;
		goto done;
	case YPBINDPROG:
		if (args->proc != YPBINDPROC_SETDOM)
			break;
		/* FALLTHROUGH */
	case YPPASSWDPROG:
	case NFS_PROGRAM:
	case RQUOTAPROG:
		ret = FALSE;
		goto done;
	case YPPROG:
		switch (args->proc) {
		case YPPROC_ALL:
		case YPPROC_MATCH:
		case YPPROC_FIRST:
		case YPPROC_NEXT:
			ret = FALSE;
			goto done;
		default:
			break;
		}
	default:
		break;
	}

	ret = TRUE;
done:
	if (!ret) {
#ifdef HAVE_LIBWRAP
		logit(deny_severity, sa, slen, args->proc, args->prog,
		      ": indirect call not allowed");
#else
		logit(0, sa, slen, args->proc, args->prog,
		      ": indirect call not allowed");
#endif
	}
	if (caller) {
		if (caller->buf) {
			free(caller->buf);
		}
		caller->buf = NULL;
		free(caller);
		caller = NULL;
	}
	return ret;
}
