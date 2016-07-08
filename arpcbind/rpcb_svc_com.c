/*	$NetBSD: rpcb_svc_com.c,v 1.9 2002/11/08 00:16:39 fvdl Exp $	*/
/*	$FreeBSD: src/usr.sbin/rpcbind/rpcb_svc_com.c,v 1.11 2003/10/29 09:30:37 mbr Exp $ */

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

/* #ident	"@(#)rpcb_svc_com.c	1.18	94/05/02 SMI" */

/*
 * rpcb_svc_com.c
 * The commom server procedure for the rpcbind.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include <libarpc/arpc.h>
#include <libarpc/svc.h>
#include "pmap_prot.h"
#include "rpcb_prot.h"
#include "rpcbind.h"

#include "compat.h"

static int rpcb_rmtcalls;

struct rmtcallfd_list {
	int fd;
	ar_svc_xprt_t *xprt;
	char *netid;
	struct rmtcallfd_list *next;
};

typedef struct rpcb_remote_result_s {
	size_t		buflen;
	off_t		off;
	char		*buf;
	int		lastlen;
} rpcb_remote_result_t;

#define NFORWARD        64
#define MAXTIME_OFF     300     /* 5 minutes */

struct finfo {
	int             	flag;
#define FINFO_ACTIVE    0x1
	ar_svc_call_obj_t	sco;
	ar_clnt_call_obj_t	cco;
	ar_client_t		*clnt;
	char			*uaddr;
	int			localvers;
	time_t          	time;
};
static struct finfo     FINFO[NFORWARD];

static int forward_register(struct finfo **infop);
static int free_slot_by_index(int);
static void free_slot(struct finfo *fi);
static void find_versions(arpcprog_t, const char *, 
			  arpcvers_t *, arpcvers_t *);
static rpcblist_ptr find_service(arpcprog_t, arpcvers_t, const char *);
static char *getowner(ar_svc_xprt_t *, char *, size_t);
static int add_pmaplist(RPCB *);
static int del_pmaplist(RPCB *);

/*
 * Set a mapping of program, version, netid
 */
/* ARGSUSED */
bool_t
rpcbproc_set_com(rpcb *regp, bool_t *result, ar_svc_req_t *rqstp,
		 arpcvers_t rpcbversnum)
{
	bool_t ans;
	char owner[64];

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCB_SET request for (%lu, %lu, %s, %s) : ",
			(unsigned long)regp->r_prog, 
			(unsigned long)regp->r_vers,
			regp->r_netid, regp->r_addr);
	}
#endif
	ans = map_set(regp, getowner(rqstp->rq_xprt, owner, sizeof owner));
#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "%s\n", ans == TRUE ? "succeeded" : "failed");
	}
#endif
	/* XXX: should have used some defined constant here */
	rpcbs_set(rpcbversnum - 2, ans);
	*result = ans;
	return TRUE;
}

bool_t
map_set(RPCB *regp, const char *owner)
{
	RPCB reg, *a;
	rpcblist_ptr rbl, fnd;

	reg = *regp;
	/*
	 * check to see if already used
	 * find_service returns a hit even if
	 * the versions don't match, so check for it
	 */
	fnd = find_service(reg.r_prog, reg.r_vers, reg.r_netid);
	if (fnd && (fnd->rpcb_map.r_vers == reg.r_vers)) {
		if (!strcmp(fnd->rpcb_map.r_addr, reg.r_addr))
			/*
			 * if these match then it is already
			 * registered so just say "OK".
			 */
			return (TRUE);
		else
			return (FALSE);
	}
	/*
	 * add to the end of the list
	 */
	rbl = malloc(sizeof (RPCBLIST));
	if (rbl == NULL)
		return (FALSE);
	a = &(rbl->rpcb_map);
	a->r_prog = reg.r_prog;
	a->r_vers = reg.r_vers;
	a->r_netid = strdup(reg.r_netid);
	a->r_addr = strdup(reg.r_addr);
	a->r_owner = strdup(owner);
	if (!a->r_addr || !a->r_netid || !a->r_owner) {
		if (a->r_netid)
			free(a->r_netid);
		if (a->r_addr)
			free(a->r_addr);
		if (a->r_owner)
			free(a->r_owner);
		free(rbl);
		return (FALSE);
	}
	rbl->rpcb_next = (rpcblist_ptr)NULL;
	if (list_rbl == NULL) {
		list_rbl = rbl;
	} else {
		for (fnd = list_rbl; fnd->rpcb_next;
			fnd = fnd->rpcb_next)
			;
		fnd->rpcb_next = rbl;
	}
#ifdef PORTMAP
	(void) add_pmaplist(regp);
#endif
	return (TRUE);
}

/*
 * Unset a mapping of program, version, netid
 */
/* ARGSUSED */
bool_t
rpcbproc_unset_com(rpcb *regp, bool_t *result, ar_svc_req_t *rqstp, 
		   arpcvers_t rpcbversnum)
{
	bool_t ans;
	char owner[64];

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCB_UNSET request for (%lu, %lu, %s) : ",
			(unsigned long)regp->r_prog, 
			(unsigned long)regp->r_vers,
			regp->r_netid);
	}
#endif
	ans = map_unset(regp, getowner(rqstp->rq_xprt, owner, sizeof owner));
#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "%s\n", ans == TRUE ? "succeeded" : "failed");
	}
#endif
	/* XXX: should have used some defined constant here */
	rpcbs_unset(rpcbversnum - 2, ans);
	*result = ans;
	return TRUE;
}

bool_t
map_unset(RPCB *regp, const char *owner)
{
	int ans = 0;
	rpcblist_ptr rbl, prev, tmp;

	if (owner == NULL)
		return (0);

	for (prev = NULL, rbl = list_rbl; rbl; /* cstyle */) {
		if ((rbl->rpcb_map.r_prog != regp->r_prog) ||
			(rbl->rpcb_map.r_vers != regp->r_vers) ||
			(regp->r_netid[0] && strcasecmp(regp->r_netid,
				rbl->rpcb_map.r_netid))) {
			/* both rbl & prev move forwards */
			prev = rbl;
			rbl = rbl->rpcb_next;
			continue;
		}
		/*
		 * Check whether appropriate uid. Unset only
		 * if superuser or the owner itself.
		 */
		if (strcmp(owner, "superuser") &&
			strcmp(rbl->rpcb_map.r_owner, owner))
			return (0);
		/* found it; rbl moves forward, prev stays */
		ans = 1;
		tmp = rbl;
		rbl = rbl->rpcb_next;
		if (prev == NULL)
			list_rbl = rbl;
		else
			prev->rpcb_next = rbl;
		free(tmp->rpcb_map.r_addr);
		free(tmp->rpcb_map.r_netid);
		free(tmp->rpcb_map.r_owner);
		free(tmp);
	}
#ifdef PORTMAP
	if (ans)
		(void) del_pmaplist(regp);
#endif
	/*
	 * We return 1 either when the entry was not there or it
	 * was able to unset it.  It can come to this point only if
	 * atleast one of the conditions is true.
	 */
	return (1);
}

void
delete_prog(unsigned int prog)
{
	RPCB reg;
	register rpcblist_ptr rbl;

	for (rbl = list_rbl; rbl != NULL; rbl = rbl->rpcb_next) {
		if ((rbl->rpcb_map.r_prog != prog))
			continue;
		if (is_bound(rbl->rpcb_map.r_netid, rbl->rpcb_map.r_addr))
			continue;
		reg.r_prog = rbl->rpcb_map.r_prog;
		reg.r_vers = rbl->rpcb_map.r_vers;
		reg.r_netid = strdup(rbl->rpcb_map.r_netid);
		(void) map_unset(&reg, "superuser");
		free(reg.r_netid);
	}
}

bool_t
rpcbproc_getaddr_com(rpcb *regp, char **result, ar_svc_req_t *rqstp, 
		     arpcvers_t rpcbversnum, arpcvers_t verstype)
{
	char *uaddr;
	char *saddr;
	const char *netidstr;
	rpcblist_ptr fnd;

	uaddr = NULL;
	saddr = NULL;

	if (!ar_svc_control(rqstp->rq_xprt,  AR_SVCGET_NETID, &netidstr)) {
		ar_svcflgerr_systemerr(rqstp);
		return FALSE;
	}

	fnd = find_service(regp->r_prog, regp->r_vers, netidstr);
	if (fnd && ((verstype == RPCB_ALLVERS) ||
		    (regp->r_vers == fnd->rpcb_map.r_vers))) {
		if (*(regp->r_addr) != '\0') {  /* may contain a hint about */
			saddr = regp->r_addr;   /* the interface that we    */
		}				/* should use */
		if (!(uaddr = mergeaddr(rqstp->rq_xprt, netidstr,
					fnd->rpcb_map.r_addr, saddr))) {
			/* Try whatever we have */
			uaddr = strdup(fnd->rpcb_map.r_addr);
		} else if (!uaddr[0]) {
			/*
			 * The server died.  Unset all versions of this prog.
			 */
			delete_prog(regp->r_prog);
			uaddr = strdup("");
		}
	} else {
		uaddr = strdup("");
	}

	if (!uaddr) {
		ar_svcflgerr_systemerr(rqstp);
		return FALSE;
	}

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "getaddr: %s\n", uaddr);
	}
#endif

	/* XXX: should have used some defined constant here */
	rpcbs_getaddr(rpcbversnum - 2, regp->r_prog, regp->r_vers,
		      netidstr, uaddr);

	*result = uaddr;
	return TRUE;
}

/* ARGSUSED */
bool_t 
rpcbproc_gettime_com(void *argp, u_int *result, 
		     ar_svc_req_t *rqstp, arpcvers_t rpcbversnum)
{
	time_t curtime;

	(void) time(&curtime);

	*result = (u_int)curtime;
	return TRUE;
}

/*
 * Convert uaddr to taddr. Should be used only by
 * local servers/clients. (kernel level stuff only)
 */
/* ARGSUSED */
bool_t
rpcbproc_uaddr2taddr_com(char **uaddrp, arpc_addr_t *result,
			 ar_svc_req_t *rqstp, arpcvers_t rpcbversnum)
{
	const char *netidstr;
	arpc_addr_t *retp;
	int err;

	if (!ar_svc_control(rqstp->rq_xprt,  AR_SVCGET_NETID, &netidstr)) {
		ar_svcflgerr_systemerr(rqstp);
		return FALSE;
	}

	err = ar_uaddr2taddr(rpcbind_ioctx, netidstr, *uaddrp, &retp);
	if (err != 0) {
		/* return empty addr */
		memset(result, 0, sizeof(*result));
		return TRUE;
	}
	*result = *retp;
	memset(retp, 0, sizeof(*retp));
	free(retp);
	return TRUE;
}

/*
 * Convert taddr to uaddr. Should be used only by
 * local servers/clients. (kernel level stuff only)
 */
/* ARGSUSED */
bool_t
rpcbproc_taddr2uaddr_com(arpc_addr_t *taddr, char **result, 
			 ar_svc_req_t *rqstp, arpcvers_t rpcbversnum)
{
	const char *netidstr;
	int err;

	if (!ar_svc_control(rqstp->rq_xprt,  AR_SVCGET_NETID, &netidstr)) {
		ar_svcflgerr_systemerr(rqstp);
		return FALSE;
	}

	err = ar_taddr2uaddr(rpcbind_ioctx, netidstr, taddr, result);
	if (err != 0) {
		*result = strdup("");
		if (!*result) {
			ar_svcflgerr_systemerr(rqstp);
			return FALSE;
		}
	}

	return TRUE;
}



static axdr_ret_t
axdr_callit_rmtcallargs(axdr_state_t *xdrs, rpcb_rmtcallargs *a)
{
	/* just need to pass through the opaque payload */
	return axdr_opaque(xdrs, a->args.args_val, a->args.args_len);
}


static axdr_ret_t
axdr_callit_rmtresult(axdr_state_t *xdrs, rpcb_remote_result_t *retp)
{
	bool_t eor;
	axdr_ret_t ret;
	char *nbuf;
	int nlen;
	off_t avail;
	off_t space;

	if (xdrs->x_op == AXDR_FREE) {
		if (retp->buf) {
			free(retp->buf);
		}
		memset(retp, 0, sizeof(*retp));
		return AXDR_DONE;
	}

	if (xdrs->x_op != AXDR_DECODE_ASYNC) {
		return AXDR_ERROR;
	}

	/* NOTE: because we are trying to capture the whole response body,
	 * we don't know the length or now to decode the response
	 * ahead of time.  We rely on the xdr framing layer to provide
	 * this information to us...
	 */
	if (retp->lastlen > 0) {
		/* have operation in progress, continue it */
		ret = axdr_getbytes(xdrs, &retp->buf[retp->off], 
				    retp->lastlen);
		if (ret != AXDR_DONE) {
			return ret;
		}
		retp->off += retp->lastlen;
		retp->lastlen = 0;
	}

	for (;;) {
		ret = axdr_control(xdrs, AR_XDRGET_EOR, &eor);
		if (ret != AXDR_DONE) {
			return ret;
		}
		if (eor) {
			/* finished */
			return AXDR_DONE;
		}

		/* determine how much more data we can currently get */
		ret = axdr_control(xdrs, AR_XDRGET_AVAIL, &avail);
		if (ret != AXDR_DONE) {
			return ret;
		}
		if (avail <= 0) {
			/* always try for some data */
			avail = 4;
		}
		/* round up to aligned size */
		avail = ((avail + 3) & (~3UL));

		space = retp->buflen - retp->off;
		if (space < avail) {
			nlen = retp->buflen + avail + 900;
			nbuf = realloc(retp->buf, nlen);
			if (!nbuf) {
				return AXDR_ERROR;
			}
			retp->buf = nbuf;
			retp->buflen = nlen;
		}

		/* setup to retry this same operation until it finishes */
		ret = axdr_getbytes(xdrs, &retp->buf[retp->off], avail);
		if (ret != AXDR_DONE) {
			retp->lastlen = avail;
			return ret;
		}
		retp->lastlen = 0;
		retp->off += avail;
	}
}

axdr_ret_t
axdr_rmtcall_result(axdr_state_t *xdrs, r_rmtcall_args_t *cap)
{
	int		off;
	axdr_ret_t	rval;
	bool_t		cleanup;
	bool_t		pmap;
	int		state = 0; 

	if (xdrs->x_op == AXDR_FREE) {
		if (cap->rmt_uaddr) {
			free(cap->rmt_uaddr);
		}
		cap->rmt_uaddr = NULL;
		if (cap->rmt_ret) {
			free(cap->rmt_ret);
		}
		cap->rmt_ret = NULL;
		memset(cap, 0, sizeof(*cap));
		return AXDR_DONE;
	}

	rval = axdr_async_setup(xdrs, &axdr_rmtcall_result, &cleanup, &state,
			       0, NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	pmap = cap->rmt_localvers == PMAPVERS;
	
	switch (state) {
	case 0:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, pmap ? 
						 ".port" : ".addr",
						 TRUE, &off);
			if (rval != AXDR_DONE) {
				return rval;
			}
		}

		if (pmap) {
			int h1, h2, h3, h4, p1, p2;
			u_long port;

			/* interpret the universal address for TCP/IP */
			if (sscanf(cap->rmt_uaddr, "%d.%d.%d.%d.%d.%d",
				   &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
				return AXDR_ERROR;
			}
			port = ((p1 & 0xff) << 8) + (p2 & 0xff);
			rval = axdr_u_long(xdrs, &port);
		} else if ((cap->rmt_localvers == RPCBVERS) ||
			   (cap->rmt_localvers == RPCBVERS4)) {
			rval = axdr_wrapstring(xdrs, &(cap->rmt_uaddr));
		} else {
			return AXDR_ERROR;
		}			
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 1;
		/* fallthrough */
	case 1:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, pmap ? 
						 ".res" : ".results",
						 FALSE, &off);
			if (rval != AXDR_DONE) {
				return rval;
			}
		}
		rval = axdr_bytes(xdrs, &(cap->rmt_ret),
				  &(cap->rmt_retlen), ~0);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}

		state = 2;
	default:
		return AXDR_ERROR;
	}

	if (rval == AXDR_DONE && xdrs->x_op == AXDR_STRINGIFY) {
		rval = axdr_str_set_name(xdrs, NULL, FALSE, &off);
		if (rval != AXDR_DONE) {
			return rval;
		}
	}

	axdr_async_teardown(xdrs, &axdr_rmtcall_result, state, cleanup, rval);
	return rval;
}


static void
rpcb_callit_done(ar_clnt_call_obj_t cco, void *arg, 
		 const arpc_err_t *stat, void *result)
{
	struct finfo *fi;
	rpcb_remote_result_t *ret;
	r_rmtcall_args_t *r;
	int err;

	fi = (struct finfo *)arg;
	ret = (rpcb_remote_result_t *)result;
	assert(ret != NULL);
	assert(fi != NULL);
	assert(fi->cco == cco);

	err = ar_svc_async_get_resultptr(fi->sco, (void **)&r);
	if (err == 0 && stat->re_status == ARPC_SUCCESS) {
		r->rmt_localvers = fi->localvers;
		r->rmt_uaddr = fi->uaddr;
		fi->uaddr = NULL;
		r->rmt_ret = ret->buf;
		r->rmt_retlen = ret->off;
		memset(ret, 0, sizeof(*ret));
		ar_svc_async_done(fi->sco, 0);
	} else {
		switch (stat->re_status) {
		case ARPC_AUTHERROR:
			ar_scoflgerr_auth(fi->sco, stat->re_why);
			break;
		case ARPC_PROGUNAVAIL:
			ar_scoflgerr_noprog(fi->sco);
			break;
		case ARPC_PROGVERSMISMATCH:
			ar_scoflgerr_progvers(fi->sco, 
					      stat->re_vers.low, 
					      stat->re_vers.high);
			break;
		case ARPC_PROCUNAVAIL:
			ar_scoflgerr_noproc(fi->sco);
			break;
		case ARPC_CANTDECODEARGS:
			ar_scoflgerr_decode(fi->sco);
			break;
		default:
			ar_scoflgerr_systemerr(fi->sco);
			break;
		}
		ar_svc_async_done(fi->sco, EINVAL);
	}
	/* reply is now going out, clean up rest of state */
	fi->sco = NULL;
	fi->cco = NULL;

	free_slot(fi);
}


/*
 * Call a remote procedure service.  This procedure is very quiet when things
 * go wrong.  The proc is written to support broadcast rpc.  In the broadcast
 * case, a machine should shut-up instead of complain, lest the requestor be
 * overrun with complaints at the expense of not hearing a valid reply.
 * When receiving a request and verifying that the service exists, we
 *
 *	receive the request
 *
 *	open a new TLI endpoint on the same transport on which we received
 *	the original request
 *
 *	remember the original request's XID (which requires knowing the format
 *	of the svc_dg_data structure)
 *
 *	forward the request, with a new XID, to the requested service,
 *	remembering the XID used to send this request (for later use in
 *	reassociating the answer with the original request), the requestor's
 *	address, the file descriptor on which the forwarded request is
 *	made and the service's address.
 *
 *	mark the file descriptor on which we anticipate receiving a reply from
 *	the service and one to select for in our private svc_run procedure
 *
 * At some time in the future, a reply will be received from the service to
 * which we forwarded the request.  At that time, we detect that the socket
 * used was for forwarding (by looking through the finfo structures to see
 * whether the fd corresponds to one of those) and call handle_reply() to
 *
 *	receive the reply
 *
 *	bundle the reply, along with the service's universal address
 *
 *	create a ar_svc_xprt_t structure and use a version of svc_sendreply
 *	that allows us to specify the reply XID and destination, send the reply
 *	to the original requestor.
 */

bool_t
rpcbproc_callit_com(rpcb_rmtcallargs *a, void *result, 
		    ar_svc_req_t *rqstp, arpcvers_t versnum)
{
	rpcblist_ptr rbl;
	ar_netid_t *nconf;
	ar_svc_xprt_t *transp;
	char *uaddr, *m_uaddr = NULL, *local_uaddr = NULL;
	arpcproc_t reply_type;
	arpc_createerr_t cerr;
	struct sockaddr_storage ss;
	struct sockaddr *localsa;
	const char *netidstr;
	struct timespec tlimit;
	arpc_addr_t caller;
	arpc_addr_t tbuf;
	arpc_addr_t *na;
	char *errstr;
	struct finfo *info;
	int err;

	caller.maxlen = sizeof(ss);
	caller.len = sizeof(ss);
	caller.buf = (char *)&ss;

	reply_type = rqstp->rq_proc;
	transp = rqstp->rq_xprt;

	if (!ar_svc_control(rqstp->rq_xprt,  AR_SVCGET_NETID, &netidstr)) {
		ar_svcflgerr_systemerr(rqstp);
		return FALSE;
	}

	if (!check_callit(rqstp, a, versnum)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	if (!ar_svc_control(rqstp->rq_xprt, AR_SVCGET_REMOTE_ADDR, &caller)) {
		ar_svcflgerr_systemerr(rqstp);
		return FALSE;
	}
		
#ifdef RPCBIND_DEBUG
	if (debugging) {
		uaddr = rqst2uaddr(rqstp);
		fprintf(stderr, "%s %s req for (%lu, %lu, %lu, %s) from %s : ",
			versnum == PMAPVERS ? "pmap_rmtcall" :
			versnum == RPCBVERS ? "rpcb_rmtcall" :
			versnum == RPCBVERS4 ? "rpcb_indirect" : "unknown",
			reply_type == RPCBPROC_INDIRECT ? "indirect" : 
			"callit",
			(unsigned long)a->rmt_prog, (unsigned long)a->rmt_vers,
			(unsigned long)a->rmt_proc, netidstr,
			uaddr ? uaddr : "unknown");
		if (uaddr) {
			free(uaddr);
		}
		uaddr = NULL;
	}
#endif
	rbl = find_service(a->prog, a->vers, netidstr);

	rpcbs_rmtcall(versnum - 2, reply_type, a->prog, a->vers,
		      a->proc, netidstr, rbl);

	if (rbl == (rpcblist_ptr)NULL) {
#ifdef RPCBIND_DEBUG
		if (debugging) {
			fprintf(stderr, "not found\n");
		}
#endif
		if (reply_type == RPCBPROC_INDIRECT) {
			ar_svcflgerr_noprog(rqstp);
		}
		return FALSE;
	}
	if (rbl->rpcb_map.r_vers != a->vers) {
		if (reply_type == RPCBPROC_INDIRECT) {
			arpcvers_t vers_low, vers_high;

			find_versions(a->prog, netidstr,
				      &vers_low, &vers_high);
			ar_svcflgerr_progvers(rqstp, vers_low, vers_high);
		}
		return FALSE;
	}

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "found at uaddr %s\n", rbl->rpcb_map.r_addr);
	}
#endif
	/*
	 *	Check whether this entry is valid and a server is present
	 *	Mergeaddr() returns NULL if no such entry is present, and
	 *	returns "" if the entry was present but the server is not
	 *	present (i.e., it crashed).
	 */
	if (reply_type == RPCBPROC_INDIRECT) {
		uaddr = mergeaddr(transp, netidstr, 
				  rbl->rpcb_map.r_addr, NULL);
		if (uaddr == NULL || uaddr[0] == '\0') {
			ar_svcflgerr_noprog(rqstp);
			if (uaddr != NULL) {
				free(uaddr);
			}
			uaddr = NULL;
			return FALSE;
		}
		free(uaddr);
		uaddr = NULL;
	}
	nconf = rpcbind_get_conf(netidstr);
	if (nconf == (ar_netid_t *)NULL) {
		if (reply_type == RPCBPROC_INDIRECT) {
			ar_svcflgerr_systemerr(rqstp);
			return FALSE;
		}
		if (debugging) {
			fprintf(stderr, "rpcbproc_callit_com:  "
				"rpcbind_get_conf failed\n");
		}
		return FALSE;
	}

	/* compute local_uaddr with merge (picks port from rbl, local address
	 * that most matches the request's src addr.
	 * 
	 * convert that back to uaddr
	 */

	localsa = local_sa(nconf->an_family, &tbuf.len);
	if (localsa == NULL) {
		if (debugging) {
			fprintf(stderr,
			"rpcbproc_callit_com: no local address\n");
		}
		goto error;
	}
	tbuf.maxlen = tbuf.len;
	tbuf.buf = (char *)localsa;
	local_uaddr = addrmerge(&tbuf, rbl->rpcb_map.r_addr, NULL, netidstr);
	if (!local_uaddr) {
		err = ENOMEM;
		goto error;
	}

	m_uaddr = addrmerge(&caller, rbl->rpcb_map.r_addr, NULL, netidstr);
	if (!m_uaddr) {
		err = ENOMEM;
		goto error;
	}

	err = ar_uaddr2taddr(rpcbind_ioctx, netidstr, local_uaddr, &na);
	if (err != 0) {
		if (reply_type == RPCBPROC_INDIRECT) {
			ar_svcflgerr_systemerr(rqstp);
		}
		goto error;
	}

	/* allocate forward table entry */
	err = forward_register(&info);
	if (err != 0) {
		goto error;
	}

	info->clnt = NULL;
	info->cco = NULL;
	info->sco = NULL;
	info->uaddr = m_uaddr;
	m_uaddr = NULL;

	/* setup/connect clnt. ar_clnt_tli_create() */
	err = ar_clnt_tli_create(rpcbind_ioctx, netidstr, na, 
				 a->prog, a->vers, NULL, &cerr,
				 &info->clnt);
	if (err != 0) {
		if (debugging) {
			errstr = ar_astrcreateerror(&cerr);
			if (errstr) {
				fprintf(stderr, "create clnt failed: %s\n",
					errstr);
				free(errstr);
			}
		}
		goto error;
	}

	tlimit.tv_sec = MAXTIME_OFF;
	tlimit.tv_nsec = 0;
	
	/* issue async rpc through clnt ar_clnt_call_async_copy */
	err = ar_clnt_call_async_copy(info->clnt, a->proc, 
				      (axdrproc_t)&axdr_callit_rmtcallargs,
				      a, (axdrproc_t)&axdr_callit_rmtresult, 
				      sizeof(rpcb_remote_result_t),
				      &rpcb_callit_done, info,
				      &tlimit, &info->cco);
	if (err != 0) {
		goto error;
	}

	/* call is running. Mark original server call as async so we
	 * can finish it when we get the result.
	 */
	err = ar_svc_async(rqstp, &info->sco);
	if (err != 0) {
		goto error;
	}

	/* done */
	info = NULL;
	err = 0;

error:
	if (err != 0 && reply_type == RPCBPROC_INDIRECT) {
		ar_svcflgerr_systemerr(rqstp);
	}

	if (local_uaddr) {
		free(local_uaddr);
		local_uaddr = NULL;
	}
	if (m_uaddr) {
		free(m_uaddr);
		m_uaddr = NULL;
	}

	if (na) {
		if (na->buf) {
			free(na->buf);
		}
		na->buf = NULL;
		free(na);
		na = NULL;
	}
	if (info) {
		if (info->cco) {
			ar_clnt_call_cancel(info->cco);
		}
		info->cco = NULL;
		if (info->sco) {
			ar_svc_async_done(info->sco, err);
		}
		info->sco = NULL;
		if (info->clnt) {
			ar_clnt_destroy(info->clnt);
		}
		info->clnt = NULL;
		if (info->uaddr) {
			free(info->uaddr);
		}
		info->uaddr = NULL;
		info->flag &= ~FINFO_ACTIVE;
		info = NULL;
	}
		
	return FALSE;
}

/*
 * Makes an entry into the FIFO for the given request.
 * Returns 0 on success, errno on failure.
 */
static int
forward_register(struct finfo **infop)
{
	time_t	min_time, time_now;
	int j;
	int i;

	if (!infop) {
		return EINVAL;
	}

	time_now = time((time_t *)0);
	min_time = 0;
	j = -1;

	for (i = 0; i < NFORWARD; i++) {
		if ((FINFO[i].flag & FINFO_ACTIVE) == 0) {
			/* free slot, use it */
			break;
		}
		if (j < 0 || FINFO[i].time < min_time) {
			min_time = FINFO[i].time;
			j = i;
		}
	}

	if (i >= NFORWARD) {
		(void) free_slot_by_index(j);
		i = j;
	}

	rpcb_rmtcalls++;	/* no of pending calls */
	FINFO[i].flag = FINFO_ACTIVE;
	FINFO[i].sco = NULL;
	FINFO[i].cco = NULL;
	FINFO[i].clnt = NULL;
	FINFO[i].uaddr = NULL;
	FINFO[i].time = time_now;

	*infop = &FINFO[i];
	return 0;
}
	

static void
free_slot(struct finfo *fi)
{
	if (fi->cco) {
		ar_clnt_call_cancel(fi->cco);
	}
	fi->cco = NULL;
	if (fi->sco) {
		ar_scoflgerr_systemerr(fi->sco);
		ar_svc_async_done(fi->sco, ETIMEDOUT);
	}
	fi->sco = NULL;
	if (fi->clnt) {
		ar_clnt_destroy(fi->clnt);
	}
	fi->clnt = NULL;
	if (fi->uaddr) {
		free(fi->uaddr);
	}
	fi->uaddr = NULL;
	fi->flag &= ~FINFO_ACTIVE;
	rpcb_rmtcalls--;
}


static int
free_slot_by_index(int index)
{
	struct finfo	*fi;
	
	if (index < 0 || index >= NFORWARD) {
		return 0;
	}

	fi = &FINFO[index];
	if (fi->flag & FINFO_ACTIVE) {
		free_slot(fi);
		return (1);
	}
	return (0);
}

static void
find_versions(arpcprog_t prog, const char *netid, 
	      arpcvers_t *lowvp, arpcvers_t *highvp)
{
	rpcblist_ptr rbl;
	unsigned int lowv = 0;
	unsigned int highv = 0;

	for (rbl = list_rbl; rbl != NULL; rbl = rbl->rpcb_next) {
		if ((rbl->rpcb_map.r_prog != prog) ||
		    ((rbl->rpcb_map.r_netid != NULL) &&
			(strcasecmp(rbl->rpcb_map.r_netid, netid) != 0)))
			continue;
		if (lowv == 0) {
			highv = rbl->rpcb_map.r_vers;
			lowv = highv;
		} else if (rbl->rpcb_map.r_vers < lowv) {
			lowv = rbl->rpcb_map.r_vers;
		} else if (rbl->rpcb_map.r_vers > highv) {
			highv = rbl->rpcb_map.r_vers;
		}
	}
	*lowvp = lowv;
	*highvp = highv;
	return;
}


/*
 * returns the item with the given program, version number and netid.
 * If that version number is not found, it returns the item with that
 * program number, so that address is now returned to the caller. The
 * caller when makes a call to this program, version number, the call
 * will fail and it will return with PROGVERS_MISMATCH. The user can
 * then determine the highest and the lowest version number for this
 * program using clnt_geterr() and use those program version numbers.
 *
 * Returns the RPCBLIST for the given prog, vers and netid
 */
static rpcblist_ptr
find_service(arpcprog_t prog, arpcvers_t vers, const char *netid)
{
	 rpcblist_ptr hit = NULL;
	 rpcblist_ptr rbl;

	for (rbl = list_rbl; rbl != NULL; rbl = rbl->rpcb_next) {
		if ((rbl->rpcb_map.r_prog != prog) ||
		    ((rbl->rpcb_map.r_netid != NULL) &&
			(strcasecmp(rbl->rpcb_map.r_netid, netid) != 0)))
			continue;
		hit = rbl;
		if (rbl->rpcb_map.r_vers == vers)
			break;
	}
	return (hit);
}

/*
 * Copies the name associated with the uid of the caller and returns
 * a pointer to it.  Similar to getwd().
 */
static char *
getowner(ar_svc_xprt_t *transp, char *owner, size_t ownersize)
{
	struct ucred ucred;
 
	if (!ar_svc_control(transp, AR_SVCGET_PEERCRED, &ucred)) {
                strlcpy(owner, "unknown", ownersize);
	} else if (ucred.uid == 0) {
		strlcpy(owner, "superuser", ownersize);
	} else {
		snprintf(owner, ownersize, "%d", ucred.uid);  
	}

	return owner;
}

/*
 * Add this to the pmap list only if it is UDP or TCP.
 */
static int
add_pmaplist(RPCB *arg)
{
	struct ar_pmap pmap;
	ar_pmaplist_t *pml;
	int h1, h2, h3, h4, p1, p2;

	if (strcmp(arg->r_netid, udptrans) == 0) {
		/* It is UDP! */
		pmap.pm_prot = IPPROTO_UDP;
	} else if (strcmp(arg->r_netid, tcptrans) == 0) {
		/* It is TCP */
		pmap.pm_prot = IPPROTO_TCP;
	} else
		/* Not an IP protocol */
		return (0);

	/* interpret the universal address for TCP/IP */
	if (sscanf(arg->r_addr, "%d.%d.%d.%d.%d.%d",
		&h1, &h2, &h3, &h4, &p1, &p2) != 6)
		return (0);
	pmap.pm_port = ((p1 & 0xff) << 8) + (p2 & 0xff);
	pmap.pm_prog = arg->r_prog;
	pmap.pm_vers = arg->r_vers;
	/*
	 * add to END of list
	 */
	pml = malloc(sizeof(*pml));
	if (pml == NULL) {
		(void) syslog(LOG_ERR, "rpcbind: no memory!\n");
		return (1);
	}
	pml->pml_map = pmap;
	pml->pml_next = NULL;
	if (list_pml == NULL) {
		list_pml = pml;
	} else {
		ar_pmaplist_t *fnd;

		/* Attach to the end of the list */
		for (fnd = list_pml; fnd->pml_next; fnd = fnd->pml_next)
			;
		fnd->pml_next = pml;
	}
	return (0);
}

/*
 * Delete this from the pmap list only if it is UDP or TCP.
 */
static int
del_pmaplist(RPCB *arg)
{
	ar_pmaplist_t *pml;
	ar_pmaplist_t *prevpml, *fnd;
	unsigned long prot;

	if (strcmp(arg->r_netid, udptrans) == 0) {
		/* It is UDP! */
		prot = IPPROTO_UDP;
	} else if (strcmp(arg->r_netid, tcptrans) == 0) {
		/* It is TCP */
		prot = IPPROTO_TCP;
	} else if (arg->r_netid[0] == 0) {
		prot = 0;	/* Remove all occurrences */
	} else {
		/* Not an IP protocol */
		return (0);
	}
	for (prevpml = NULL, pml = list_pml; pml; /* cstyle */) {
		if ((pml->pml_map.pm_prog != arg->r_prog) ||
			(pml->pml_map.pm_vers != arg->r_vers) ||
			(prot && (pml->pml_map.pm_prot != prot))) {
			/* both pml & prevpml move forwards */
			prevpml = pml;
			pml = pml->pml_next;
			continue;
		}
		/* found it; pml moves forward, prevpml stays */
		fnd = pml;
		pml = pml->pml_next;
		if (prevpml == NULL)
			list_pml = pml;
		else
			prevpml->pml_next = pml;
		free(fnd);
	}
	return (0);
}
