/*	$NetBSD: pmap_svc.c,v 1.2 2000/10/20 11:49:40 fvdl Exp $	*/
/*	$FreeBSD: src/usr.sbin/rpcbind/pmap_svc.c,v 1.4 2002/10/07 02:56:59 alfred Exp $ */

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

/* #ident	"@(#)pmap_svc.c	1.14	93/07/05 SMI" */

#if 0
#ifndef lint
static	char sccsid[] = "@(#)pmap_svc.c 1.23 89/04/05 Copyr 1984 Sun Micro";
#endif
#endif

/*
 * pmap_svc.c
 * The server procedure for the version 2 portmaper.
 * All the portmapper related interface from the portmap side.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <libarpc/arpc.h>
#include "pmap_prot.h"
#include "rpcb_prot.h"
#include "rpcbind.h"

#include "compat.h"

static ar_pmaplist_t *find_service_pmap __P((arpcprog_t, arpcvers_t,
					       arpcprot_t));
static bool_t ar_pmapproc_change(ar_pmap *argp, bool_t *result, ar_svc_req_t *rqstp);

static bool_t ar_pmapproc_getport_2_local(ar_pmap *argp, u_long *result, 
				       ar_svc_req_t *rqstp);
static bool_t ar_pmapproc_dump_2_local(void  *argp, ar_pmaplist_ptr *result, 
				    ar_svc_req_t *rqstp);

static bool_t
ar_pmapproc_null_local(void *dummy, void *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_2_STAT, rqstp->rq_proc);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "PMAPPROC_NULL\n");
	}
#endif

	check_access(rqstp, NULL, PMAPVERS);

	return TRUE;
}


static bool_t
ar_pmapproc_callit_2_local(rpcb_rmtcallargs *argp, void *result,
			   ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_2_STAT, rqstp->rq_proc);

	return rpcbproc_callit_com(argp, result, rqstp, PMAPVERS);
}


void
pmap_lookup(u_int32_t proc, ar_svc_handler_fn_t *handler, 
	    axdrproc_t * inproc, axdrproc_t * outproc, int * inlen,
	    int * outlen)
{
	switch (proc) {
	case AR_PMAPPROC_NULL:
		*inproc = (axdrproc_t) axdr_void;
		*outproc = (axdrproc_t) axdr_void;
		*handler = (ar_svc_handler_fn_t)ar_pmapproc_null_local;
		*inlen = 0;
		*outlen = 0;
		break;

	case AR_PMAPPROC_SET:
		*inproc = (axdrproc_t) axdr_ar_pmap;
		*outproc = (axdrproc_t) axdr_bool;
		*handler = (ar_svc_handler_fn_t)ar_pmapproc_change;
		*inlen = sizeof(ar_pmap );
		*outlen = sizeof(bool_t );
		break;

	case AR_PMAPPROC_UNSET:
		*inproc = (axdrproc_t) axdr_ar_pmap;
		*outproc = (axdrproc_t) axdr_bool;
		*handler = (ar_svc_handler_fn_t)ar_pmapproc_change;
		*inlen = sizeof(ar_pmap );
		*outlen = sizeof(bool_t );
		break;

	case AR_PMAPPROC_GETPORT:
		*inproc = (axdrproc_t) axdr_ar_pmap;
		*outproc = (axdrproc_t) axdr_u_long;
		*handler = (ar_svc_handler_fn_t)ar_pmapproc_getport_2_local;
		*inlen = sizeof(ar_pmap );
		*outlen = sizeof(u_long );
		break;

	case AR_PMAPPROC_DUMP:
		*inproc = (axdrproc_t) axdr_void;
		*outproc = (axdrproc_t) axdr_ar_pmaplist_ptr;
		*handler = (ar_svc_handler_fn_t)ar_pmapproc_dump_2_local;
		*inlen = 0;
		*outlen = sizeof(ar_pmaplist_ptr );
		break;

	case AR_PMAPPROC_CALLIT:
		*inproc = (axdrproc_t)axdr_rpcb_rmtcallargs;
		*outproc = (axdrproc_t)axdr_rmtcall_result;
		*handler = (ar_svc_handler_fn_t)ar_pmapproc_callit_2_local;
		*inlen = sizeof(rpcb_rmtcallargs);
		*outlen = sizeof(r_rmtcall_args_t);
		break;

	default:
		*inproc = (axdrproc_t)0;
		*outproc = (axdrproc_t)0;
		*handler = (ar_svc_handler_fn_t)NULL;
		*inlen = 0;
		*outlen = 0;
	}
	return;
}

/*
 * returns the item with the given program, version number. If that version
 * number is not found, it returns the item with that program number, so that
 * the port number is now returned to the caller. The caller when makes a
 * call to this program, version number, the call will fail and it will
 * return with PROGVERS_MISMATCH. The user can then determine the highest
 * and the lowest version number for this program using clnt_geterr() and
 * use those program version numbers.
 */
static ar_pmaplist_t *
find_service_pmap(arpcprog_t prog, arpcvers_t vers, arpcprot_t prot)
{
	ar_pmaplist_t *hit = NULL;
	ar_pmaplist_t *pml;

	for (pml = list_pml; pml != NULL; pml = pml->pml_next) {
		if ((pml->pml_map.pm_prog != prog) ||
			(pml->pml_map.pm_prot != prot))
			continue;
		hit = pml;
		if (pml->pml_map.pm_vers == vers)
			break;
	}
	return (hit);
}

static bool_t
ar_pmapproc_change(ar_pmap *reg, bool_t *result, ar_svc_req_t *rqstp)
{
	RPCB rpcbreg;
	long ans;
	struct sockaddr_storage iaddr;
	struct sockaddr_in *who;
	struct ucred ucred;
	arpc_addr_t addr;
	arpcproc_t op;
	char uidbuf[32];

	rpcbs_procinfo(RPCBVERS_2_STAT, rqstp->rq_proc);

	op = rqstp->rq_proc;

#ifdef RPCBIND_DEBUG
	if (debugging)
		fprintf(stderr, "%s request for (%lu, %lu) : ",
			op == AR_PMAPPROC_SET ? "PMAP_SET" : "PMAP_UNSET",
			reg->pm_prog, reg->pm_vers);
#endif

	if (!check_access(rqstp, reg, PMAPVERS)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	addr.len = sizeof(iaddr);
	addr.maxlen = sizeof(iaddr);
	addr.buf = (char *)&iaddr;
	if (!ar_svc_control(rqstp->rq_xprt, AR_SVCGET_REMOTE_ADDR, &addr)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}		

	who = (struct sockaddr_in *)&iaddr;

	/*
	 * Can't use getpwnam here. We might end up calling ourselves
	 * and looping.
	 */
	if (!ar_svc_control(rqstp->rq_xprt, AR_SVCGET_PEERCRED, &ucred)) {
		rpcbreg.r_owner = "unknown";
	} else if (ucred.uid == 0) {
		rpcbreg.r_owner = "superuser";
	} else {
		/* r_owner will be strdup-ed later */
		snprintf(uidbuf, sizeof uidbuf, "%d", ucred.uid);
		rpcbreg.r_owner = uidbuf;
	}

	rpcbreg.r_prog = reg->pm_prog;
	rpcbreg.r_vers = reg->pm_vers;

	if (op == AR_PMAPPROC_SET) {
		char buf[32];

		snprintf(buf, sizeof buf, "0.0.0.0.%d.%d",
		    (int)((reg->pm_port >> 8) & 0xff),
		    (int)(reg->pm_port & 0xff));
		rpcbreg.r_addr = buf;
		if (reg->pm_prot == IPPROTO_UDP) {
			rpcbreg.r_netid = udptrans;
		} else if (reg->pm_prot == IPPROTO_TCP) {
			rpcbreg.r_netid = tcptrans;
		} else {
			ans = FALSE;
			goto done_change;
		}
		ans = map_set(&rpcbreg, rpcbreg.r_owner);
	} else if (op == AR_PMAPPROC_UNSET) {
		bool_t ans1, ans2;

		rpcbreg.r_addr = NULL;
		rpcbreg.r_netid = tcptrans;
		ans1 = map_unset(&rpcbreg, rpcbreg.r_owner);
		rpcbreg.r_netid = udptrans;
		ans2 = map_unset(&rpcbreg, rpcbreg.r_owner);
		ans = ans1 || ans2;
	} else {
		ans = FALSE;
	}
done_change:
	*result = ans;

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "%s\n", ans == TRUE ? "succeeded" : "failed");
	}
#endif
	if (op == AR_PMAPPROC_SET) {
		rpcbs_set(RPCBVERS_2_STAT, ans);
	} else {
		rpcbs_unset(RPCBVERS_2_STAT, ans);
	}
	return (TRUE);
}

/* ARGSUSED */
static bool_t
ar_pmapproc_getport_2_local(ar_pmap *reg, u_long *result, ar_svc_req_t *rqstp)
{
	int port = 0;
	ar_pmaplist_t *fnd;

	rpcbs_procinfo(RPCBVERS_2_STAT, rqstp->rq_proc);

	if (!check_access(rqstp, reg, PMAPVERS)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

#ifdef RPCBIND_DEBUG
	if (debugging) {
		char *uaddr;

		uaddr = rqst2uaddr(rqstp);
		fprintf(stderr, "PMAP_GETPORT req for (%lu, %lu, %s)"
			" from %s :", reg->pm_prog, reg->pm_vers,
			reg->pm_prot == IPPROTO_UDP ? "udp" : 
			"tcp", uaddr != NULL ? uaddr : "<unknown>");
		if (uaddr) {
			free(uaddr);
			uaddr = NULL;
		}
	}
#endif
	fnd = find_service_pmap(reg->pm_prog, reg->pm_vers, reg->pm_prot);
	if (fnd) {
		char serveuaddr[32], *ua;
		int h1, h2, h3, h4, p1, p2;
		char *netid;

		if (reg->pm_prot == IPPROTO_UDP) {
			ua = udp_uaddr;
			netid = udptrans;
		} else {
			ua = tcp_uaddr; /* To get the len */
			netid = tcptrans;
		}
		if (ua == NULL) {
			goto done;
		}
		if (sscanf(ua, "%d.%d.%d.%d.%d.%d", &h1, &h2, &h3,
				&h4, &p1, &p2) == 6) {
			p1 = (fnd->pml_map.pm_port >> 8) & 0xff;
			p2 = (fnd->pml_map.pm_port) & 0xff;
			snprintf(serveuaddr, sizeof serveuaddr,
			    "%d.%d.%d.%d.%d.%d", h1, h2, h3, h4, p1, p2);
			if (is_bound(netid, serveuaddr)) {
				port = fnd->pml_map.pm_port;
			} else { /* this service is dead; delete it */
				delete_prog(reg->pm_prog);
			}
		}
	}
done:
	*result = port;

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "port = %d\n", port);
	}
#endif
	rpcbs_getaddr(RPCBVERS_2_STAT, reg->pm_prog, reg->pm_vers,
		      reg->pm_prot == IPPROTO_UDP ? udptrans : tcptrans,
		      port ? udptrans : "");

	return (TRUE);
}


static int 
pmapproc_copy_pmaplistent(ar_pmaplist_t *orig, ar_pmaplist_t **newp)
{
	ar_pmaplist_t *new;

	if (!orig || !newp) {
		return EINVAL;
	}

	new = malloc(sizeof(*new));
	if (!new) {
		return ENOMEM;
	}

	memset(new, 0, sizeof(*new));
	memcpy(&new->pml_map, &orig->pml_map, sizeof(new->pml_map));

	*newp = new;
	return 0;
}

static int 
pmapproc_copy_pmaplist(ar_pmaplist_t *orig, ar_pmaplist_t **newp)
{
	ar_pmaplist_t *ent;
	ar_pmaplist_t *tail;
	ar_pmaplist_t *tmp;
	int err;

	tail = NULL;
	*newp = NULL;
	
	for (ent = orig; ent != NULL; ent = ent->pml_next) {
		err = pmapproc_copy_pmaplistent(ent, &tmp);
		if (err != 0) {
			if (*newp != NULL) {
				axdr_free((axdrproc_t)
					  &axdr_ar_pmaplist_ptr, newp);
				*newp = NULL;
			}
			return err;
		}
		if (tail) {
			tail->pml_next = tmp;
		} else {
			*newp = tmp;
		}
		tail = tmp;
		tmp->pml_next = NULL;
	}

	return 0;
}


/* ARGSUSED */
static bool_t
ar_pmapproc_dump_2_local(void  *argp, ar_pmaplist_ptr *result, 
			 ar_svc_req_t *rqstp)
{
	ar_pmaplist_t *list;
	int err;

	rpcbs_procinfo(RPCBVERS_2_STAT, rqstp->rq_proc);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "PMAPPROC_DUMP\n");
	}
#endif
	if (!check_access(rqstp, argp, PMAPVERS)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	/* FIXME: dup the list for async return */
	err = pmapproc_copy_pmaplist(list_pml, &list);
	if (err != 0) {
		ar_svcflgerr_systemerr(rqstp);
		return FALSE;
	}

	*result = list;
	return (TRUE);
}
