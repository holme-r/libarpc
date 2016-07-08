/*	$NetBSD: rpcb_svc.c,v 1.1 2000/06/02 23:15:41 fvdl Exp $	*/
/*	$FreeBSD: src/usr.sbin/rpcbind/rpcb_svc.c,v 1.2 2002/10/07 02:56:59 alfred Exp $ */

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

/* #ident	"@(#)rpcb_svc.c	1.16	93/07/05 SMI" */

/*
 * rpcb_svc.c
 * The server procedure for the version 3 rpcbind (TLI).
 *
 * It maintains a separate list of all the registered services with the
 * version 3 of rpcbind.
 */
#include <sys/types.h>
#include <libarpc/arpc.h>
#include "rpcb_prot.h"
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rpcbind.h"

static bool_t rpcbproc_getaddr_3_local(rpcb *regp, char **result, 
				       ar_svc_req_t *rqstp);
static bool_t rpcbproc_dump_3_local(void *arg, rpcblist_ptr *ptr, 
				    ar_svc_req_t *rqstp);

static bool_t
rpcbproc_null_3_local(void *dummy, void *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_3_STAT, rqstp->rq_proc);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_NULL\n");
	}
#endif
	/* This call just logs, no actual checks */
	check_access(rqstp, NULL, RPCBVERS);
	return TRUE;
}

static bool_t
rpcbproc_set_3_local(rpcb  *argp, bool_t *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_3_STAT, rqstp->rq_proc);

	if (!check_access(rqstp, argp, RPCBVERS)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_set_com(argp, result, rqstp, RPCBVERS);
}

static bool_t
rpcbproc_unset_3_local(rpcb  *argp, bool_t *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_3_STAT, rqstp->rq_proc);

	if (!check_access(rqstp, argp, RPCBVERS)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_unset_com(argp, result, rqstp, RPCBVERS);
}

static bool_t
rpcbproc_callit_3_local(rpcb_rmtcallargs  *argp, 
		       void *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_3_STAT, rqstp->rq_proc);

	if (!check_access(rqstp, argp, RPCBVERS)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_callit_com(argp, result, rqstp, RPCBVERS);
}

static bool_t
rpcbproc_gettime_3_local(void *argp, u_int *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_3_STAT, rqstp->rq_proc);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_GETTIME\n");
	}
#endif
	if (!check_access(rqstp, argp, RPCBVERS)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_gettime_com(argp, result, rqstp, RPCBVERS);
}

static bool_t
rpcbproc_uaddr2taddr_3_local(char **argp, arpc_addr_t *result, 
			     ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_3_STAT, rqstp->rq_proc);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_UADDR2TADDR\n");
	}
#endif

	if (!check_access(rqstp, argp, RPCBVERS)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_uaddr2taddr_com(argp, result, rqstp, RPCBVERS);
}

static bool_t
rpcbproc_taddr2uaddr_3_local(arpc_addr_t *argp, char **result,
			     ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_3_STAT, rqstp->rq_proc);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_TADDR2UADDR\n");
	}
#endif

	if (!check_access(rqstp, argp, RPCBVERS)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_taddr2uaddr_com(argp, result, rqstp, RPCBVERS);
}

void
rpcbprog_3_lookup(u_int32_t proc, ar_svc_handler_fn_t *handler, 
		  axdrproc_t * inproc, axdrproc_t * outproc, 
		  int * inlen, int * outlen)
{
	switch (proc) {
	case AR_NULLPROC:
		*inproc = (axdrproc_t)axdr_void;
		*outproc = (axdrproc_t)axdr_void;
		*handler = (ar_svc_handler_fn_t)rpcbproc_null_3_local;
		*inlen = 0;
		*outlen = 0;
		break;

	case RPCBPROC_SET:
		*inproc = (axdrproc_t) axdr_rpcb;
		*outproc = (axdrproc_t) axdr_bool;
		*handler = (ar_svc_handler_fn_t)rpcbproc_set_3_local;
		*inlen = sizeof(rpcb);
		*outlen = sizeof(bool_t);
		break;

	case RPCBPROC_UNSET:
		*inproc = (axdrproc_t) axdr_rpcb;
		*outproc = (axdrproc_t) axdr_bool;
		*handler = (ar_svc_handler_fn_t)rpcbproc_unset_3_local;
		*inlen = sizeof(rpcb);
		*outlen = sizeof(bool_t);
		break;

	case RPCBPROC_GETADDR:
		*inproc = (axdrproc_t) axdr_rpcb;
		*outproc = (axdrproc_t) axdr_wrapstring;
		*handler = (ar_svc_handler_fn_t)rpcbproc_getaddr_3_local;
		*inlen = sizeof(rpcb );
		*outlen = sizeof(char *);
		break;

	case RPCBPROC_DUMP:
		*inproc = (axdrproc_t) axdr_void;
		*outproc = (axdrproc_t) axdr_rpcblist_ptr;
		*handler = (ar_svc_handler_fn_t)rpcbproc_dump_3_local;
		*inlen = 0;
		*outlen = sizeof(rpcblist_ptr );
		break;

	case RPCBPROC_CALLIT:
		*inproc = (axdrproc_t)axdr_rpcb_rmtcallargs;
		*outproc = (axdrproc_t)axdr_rmtcall_result;
		*handler = (ar_svc_handler_fn_t)rpcbproc_callit_3_local;
		*inlen = sizeof(rpcb_rmtcallargs);
		*outlen = sizeof(r_rmtcall_args_t);
		break;

	case RPCBPROC_GETTIME:
		*inproc = (axdrproc_t) axdr_void;
		*outproc = (axdrproc_t) axdr_u_int;
		*handler = (ar_svc_handler_fn_t)rpcbproc_gettime_3_local;
		*inlen = 0;
		*outlen = sizeof(u_int);
		break;

	case RPCBPROC_UADDR2TADDR:
		*inproc = (axdrproc_t) axdr_wrapstring;
		*outproc = (axdrproc_t) axdr_arpc_addr_t;
		*handler = (ar_svc_handler_fn_t)rpcbproc_uaddr2taddr_3_local;
		*inlen = sizeof(char *);
		*outlen = sizeof(arpc_addr_t);
		break;

	case RPCBPROC_TADDR2UADDR:
		*inproc = (axdrproc_t) axdr_arpc_addr_t;
		*outproc = (axdrproc_t) axdr_wrapstring;
		*handler = (ar_svc_handler_fn_t)rpcbproc_taddr2uaddr_3_local;
		*inlen = sizeof(arpc_addr_t );
		*outlen = sizeof(char *);
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
 * Lookup the mapping for a program, version and return its
 * address. Assuming that the caller wants the address of the
 * server running on the transport on which the request came.
 *
 * We also try to resolve the universal address in terms of
 * address of the caller.
 */
/* ARGSUSED */
static bool_t
rpcbproc_getaddr_3_local(rpcb *regp, char **result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_3_STAT, rqstp->rq_proc);

	if (!check_access(rqstp, regp, RPCBVERS)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

#ifdef RPCBIND_DEBUG
	if (debugging) {
		char *uaddr;

		uaddr = rqst2uaddr(rqstp);
		fprintf(stderr, "RPCB_GETADDR req for (%lu, %lu, %s) "
			"from %s: ", (unsigned long)regp->r_prog, 
			(unsigned long)regp->r_vers,
			regp->r_netid, uaddr != NULL ? uaddr : "<unknown>");
		if (uaddr) {
			free(uaddr);
			uaddr = NULL;
		}
	}
#endif
	return (rpcbproc_getaddr_com(regp, result, rqstp, RPCBVERS,
				     RPCB_ALLVERS));
}

/* ARGSUSED */
static bool_t 
rpcbproc_dump_3_local(void *arg, rpcblist_ptr *ptr, ar_svc_req_t *rqstp)
{
	int err;

	rpcbs_procinfo(RPCBVERS_3_STAT, rqstp->rq_proc);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_DUMP\n");
	}
#endif

	if (!check_access(rqstp, NULL, RPCBVERS)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}


	err = rpcbproc_copy_rpcb_list(list_rbl, ptr);
	if (err != 0) {
		return FALSE;
	} else {
		return TRUE;
	}
}
