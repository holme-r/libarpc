/*
 * $NetBSD: rpcb_svc_4.c,v 1.1 2000/06/02 23:15:41 fvdl Exp $
 * $FreeBSD: src/usr.sbin/rpcbind/rpcb_svc_4.c,v 1.4 2002/10/07 02:56:59 alfred Exp $
 */

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

/* #ident	"@(#)rpcb_svc_4.c	1.8	93/07/05 SMI" */

/*
 * rpcb_svc_4.c
 * The server procedure for the version 4 rpcbind.
 *
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <libarpc/arpc.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include "rpcbind.h"


static bool_t rpcbproc_getaddr_4_local(rpcb *argp, char **result, 
				       ar_svc_req_t *rqstp);
static bool_t rpcbproc_dump_4_local(void *argp, rpcblist_ptr *ptr,
				    ar_svc_req_t *rqstp);
static bool_t rpcbproc_getversaddr_4_local(rpcb *argp, char **result,
					   ar_svc_req_t *rqstp);
static bool_t rpcbproc_getaddrlist_4_local(rpcb *argp, 
					   rpcb_entry_list_ptr *result,
					   ar_svc_req_t *rqstp);
static bool_t
rpcbproc_null_4_local(void *dummy, void *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_4_STAT, AR_NULLPROC);

#ifdef RPCBIND_DEBUG
	if (debugging)
		fprintf(stderr, "RPCBPROC_NULL\n");
#endif

	/* Just log auth errors in null procedure... */
	check_access(rqstp, NULL, RPCBVERS4);
	return TRUE;
}

static bool_t
rpcbproc_set_4_local(rpcb  *argp, bool_t *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_SET);

	if (!check_access(rqstp, argp, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_set_com(argp, result, rqstp, RPCBVERS4);
}

static bool_t
rpcbproc_unset_4_local(rpcb  *argp, bool_t *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_UNSET);

	if (!check_access(rqstp, argp, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_unset_com(argp, result, rqstp, RPCBVERS4);
}


static bool_t
rpcbproc_bcast_4_local(rpcb_rmtcallargs  *argp, 
		       void *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_BCAST);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_BCAST\n");
	}
#endif

	if (!check_access(rqstp, argp, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_callit_com(argp, result, rqstp, RPCBVERS4);
}

static bool_t
rpcbproc_gettime_4_local(void  *argp, u_int *result, ar_svc_req_t *rqstp)
{

	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_GETTIME);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_GETTIME\n");
	}
#endif

	if (!check_access(rqstp, argp, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_gettime_com(argp, result, rqstp, RPCBVERS4);
}

static bool_t
rpcbproc_uaddr2taddr_4_local(char * *argp, arpc_addr_t *result,
			     ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_UADDR2TADDR);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_UADDR2TADDR\n");
	}
#endif
	if (!check_access(rqstp, argp, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_uaddr2taddr_com(argp, result, rqstp, RPCBVERS4);
}

static bool_t
rpcbproc_taddr2uaddr_4_local(arpc_addr_t  *argp, char **result, 
			     ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_TADDR2UADDR);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_TADDR2UADDR\n");
	}
#endif
	if (!check_access(rqstp, argp, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_taddr2uaddr_com(argp, result, rqstp, RPCBVERS4);
}

static bool_t
rpcbproc_indirect_4_local(rpcb_rmtcallargs  *argp, 
			  void *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_INDIRECT);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_INDIRECT\n");
	}
#endif

	if (!check_access(rqstp, argp, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_callit_com(argp, result, rqstp, RPCBVERS4);
}

static bool_t
rpcbproc_getstat_4_local(void  *argp, rpcb_stat_byvers *result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_GETSTAT);

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_GETSTAT\n");
	}
#endif
	if (!check_access(rqstp, argp, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	return rpcbproc_getstat(argp, result, rqstp, RPCBVERS4);
}

void
rpcbprog_4_lookup(u_int32_t proc, ar_svc_handler_fn_t *handler, 
		  axdrproc_t * inproc, axdrproc_t * outproc, int * inlen,
		  int * outlen)
{
	switch (proc) {
	case AR_NULLPROC:
		*inproc = (axdrproc_t)axdr_void;
		*outproc = (axdrproc_t)axdr_void;
		*handler = (ar_svc_handler_fn_t)rpcbproc_null_4_local;
		*inlen = 0;
		*outlen = 0;
		break;

	case RPCBPROC_SET:
		*inproc = (axdrproc_t)axdr_rpcb;
		*outproc = (axdrproc_t)axdr_bool;
		*handler = (ar_svc_handler_fn_t)rpcbproc_set_4_local;
		*inlen = sizeof(rpcb);
		*outlen = sizeof(bool_t);
		break;

	case RPCBPROC_UNSET:
		*inproc = (axdrproc_t)axdr_rpcb;
		*outproc = (axdrproc_t)axdr_bool;
		*handler = (ar_svc_handler_fn_t)rpcbproc_unset_4_local;
		*inlen = sizeof(rpcb);
		*outlen = sizeof(bool_t);
		break;

	case RPCBPROC_GETADDR:
		*inproc = (axdrproc_t)axdr_rpcb;
		*outproc = (axdrproc_t)axdr_wrapstring;
		*handler = (ar_svc_handler_fn_t)rpcbproc_getaddr_4_local;
		*inlen = sizeof(rpcb );
		*outlen = sizeof(char *);
		break;

	case RPCBPROC_DUMP:
		*inproc = (axdrproc_t) axdr_void;
		*outproc = (axdrproc_t) axdr_rpcblist_ptr;
		*handler = (ar_svc_handler_fn_t)rpcbproc_dump_4_local;
		*inlen = 0;
		*outlen = sizeof(rpcblist_ptr );
		break;

/*	case RPCBPROC_CALLIT: */
	case RPCBPROC_BCAST:
		*inproc = (axdrproc_t)axdr_rpcb_rmtcallargs;
		*outproc = (axdrproc_t)axdr_rmtcall_result;
		*handler = (ar_svc_handler_fn_t)rpcbproc_bcast_4_local;
		*inlen = sizeof(rpcb_rmtcallargs);
		*outlen = sizeof(r_rmtcall_args_t);
		break;

	case RPCBPROC_GETTIME:
		*inproc = (axdrproc_t) axdr_void;
		*outproc = (axdrproc_t) axdr_u_int;
		*handler = (ar_svc_handler_fn_t)rpcbproc_gettime_4_local;
		*inlen = 0;
		*outlen = sizeof(u_int );
		break;

	case RPCBPROC_UADDR2TADDR:
		*inproc = (axdrproc_t) axdr_wrapstring;
		*outproc = (axdrproc_t) axdr_arpc_addr_t;
		*handler = (ar_svc_handler_fn_t)rpcbproc_uaddr2taddr_4_local;
		*inlen = sizeof(char *);
		*outlen = sizeof(arpc_addr_t);
		break;

	case RPCBPROC_TADDR2UADDR:
		*inproc = (axdrproc_t) axdr_arpc_addr_t;
		*outproc = (axdrproc_t) axdr_wrapstring;
		*handler = (ar_svc_handler_fn_t)rpcbproc_taddr2uaddr_4_local;
		*inlen = sizeof(arpc_addr_t );
		*outlen = sizeof(char *);
		break;

	case RPCBPROC_GETVERSADDR:
		*inproc = (axdrproc_t) axdr_rpcb;
		*outproc = (axdrproc_t) axdr_wrapstring;
		*handler = (ar_svc_handler_fn_t)rpcbproc_getversaddr_4_local;
		*inlen = sizeof(rpcb );
		*outlen = sizeof(char *);
		break;

	case RPCBPROC_INDIRECT:
		*inproc = (axdrproc_t)axdr_rpcb_rmtcallargs;
		*outproc = (axdrproc_t)axdr_rmtcall_result;
		*handler = (ar_svc_handler_fn_t)rpcbproc_indirect_4_local;
		*inlen = sizeof(rpcb_rmtcallargs);
		*outlen = sizeof(r_rmtcall_args_t);
		break;

	case RPCBPROC_GETADDRLIST:
		*inproc = (axdrproc_t) axdr_rpcb;
		*outproc = (axdrproc_t) axdr_rpcb_entry_list_ptr;
		*handler = (ar_svc_handler_fn_t)rpcbproc_getaddrlist_4_local;
		*inlen = sizeof(rpcb );
		*outlen = sizeof(rpcb_entry_list_ptr );
		break;

	case RPCBPROC_GETSTAT:
		*inproc = (axdrproc_t) axdr_void;
		*outproc = (axdrproc_t) axdr_rpcb_stat_byvers;
		*handler = (ar_svc_handler_fn_t)rpcbproc_getstat_4_local;
		*inlen = 0;
		*outlen = sizeof(rpcb_stat_byvers );
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
 * Even if a service with a different version number is available,
 * it will return that address.  The client should check with an
 * clnt_call to verify whether the service is the one that is desired.
 * We also try to resolve the universal address in terms of
 * address of the caller.
 */
/* ARGSUSED */
static bool_t
rpcbproc_getaddr_4_local(rpcb *regp, char **result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_GETADDR);

	if (!check_access(rqstp, regp, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

#ifdef RPCBIND_DEBUG
	if (debugging) {
		char *uaddr;
		fprintf(stderr, "RPCBPROC_GETVERSADDR\n");

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

	return (rpcbproc_getaddr_com(regp, result, rqstp, RPCBVERS4,
				     RPCB_ALLVERS));
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
static int
rpcbproc_getversaddr_4_local(rpcb *regp, char **result, ar_svc_req_t *rqstp)
{
	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_GETVERSADDR);

	if (!check_access(rqstp, regp, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

#ifdef RPCBIND_DEBUG
	if (debugging) {
		char *uaddr;
		fprintf(stderr, "RPCBPROC_GETVERSADDR\n");

		uaddr = rqst2uaddr(rqstp);
		fprintf(stderr, "RPCB_GETVERSADDR rqst for (%lu, %lu, %s)"
			" from %s : ", (unsigned long)regp->r_prog, 
			(unsigned long)regp->r_vers,
			regp->r_netid, uaddr != NULL ? uaddr : "<unknown>");
		if (uaddr) {
			free(uaddr);
			uaddr = NULL;
		}
	}
#endif
	return (rpcbproc_getaddr_com(regp, result, rqstp, RPCBVERS4,
				     RPCB_ONEVERS));
}

/*
 * Lookup the mapping for a program, version and return the
 * addresses for all transports in the current transport family.
 * We return a merged address.
 */
/* ARGSUSED */
static bool_t
rpcbproc_getaddrlist_4_local(rpcb *regp, rpcb_entry_list_ptr *result, 
			     ar_svc_req_t *rqstp)
{
	rpcb_entry_list_ptr rlist;
	register rpcblist_ptr rbl;
	rpcb_entry_list_ptr rp, tail;
	ar_svc_xprt_t *transp;
	arpcprog_t prog;
	arpcvers_t vers;
	rpcb_entry *a;
	ar_netid_t *nconf;
	ar_netid_t *reg_nconf;
	const char *netid;
	char *saddr, *maddr = NULL;

	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_GETADDRLIST);

	if (!check_access(rqstp, regp, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

	transp = rqstp->rq_xprt;

	tail = NULL;
	rlist = NULL;
	netid = NULL;
	prog = regp->r_prog;
	vers = regp->r_vers;

	if (ar_svc_control(transp, AR_SVCGET_NETID, (void *)&netid)) {
		reg_nconf = rpcbind_get_conf(netid);
	} else {
		reg_nconf = NULL;
	}
	if (reg_nconf == NULL) {
		*result = NULL;
		return TRUE;
	}

	if (*(regp->r_addr) != '\0') {
		saddr = regp->r_addr;
	} else {
		saddr = NULL;
	}
#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_GETADDRLIST\n");

		fprintf(stderr, "r_addr: %s r_netid: %s nc_protofmly: %s\n",
			regp->r_addr, regp->r_netid, 
			reg_nconf->an_familyname);
	}
#endif
	for (rbl = list_rbl; rbl != NULL; rbl = rbl->rpcb_next) {
	    if ((rbl->rpcb_map.r_prog == prog) &&
		(rbl->rpcb_map.r_vers == vers)) {
		nconf = rpcbind_get_conf(rbl->rpcb_map.r_netid);
		if (nconf == NULL) {
			goto fail;
		}
		if (strcmp(nconf->an_familyname, reg_nconf->an_familyname)
				!= 0) {
			continue;	/* not same proto family */
		}
#ifdef RPCBIND_DEBUG
		if (debugging) {
			fprintf(stderr, "\tmerge with: %s\n",
			    rbl->rpcb_map.r_addr);
		}
#endif
		if ((maddr = mergeaddr(transp, rbl->rpcb_map.r_netid,
				rbl->rpcb_map.r_addr, saddr)) == NULL) {
#ifdef RPCBIND_DEBUG
			if (debugging) {
				fprintf(stderr, " FAILED\n");
			}
#endif
			continue;
		} else if (!maddr[0]) {
#ifdef RPCBIND_DEBUG
			if (debugging)
				fprintf(stderr, " SUCCEEDED, but port "
					"died -  maddr: nullstring\n");
#endif
			/* The server died. Unset this combination */
			free(maddr);
			maddr = NULL;
			delete_prog(regp->r_prog);
			continue;
		}
#ifdef RPCBIND_DEBUG
		if (debugging) {
			fprintf(stderr, " SUCCEEDED maddr: %s\n", maddr);
		}
#endif
		/*
		 * Add it to rlist.
		 */
		rp = malloc(sizeof (rpcb_entry_list));
		if (rp == NULL) {
			free(maddr);
			maddr = NULL;
			goto fail;
		}
		a = &rp->rpcb_entry_map;
		a->r_maddr = maddr;
		a->r_nc_netid = strdup(nconf->an_netid);
		a->r_nc_semantics = nconf->an_semantics;
		a->r_nc_protofmly = strdup(nconf->an_familyname);
		a->r_nc_proto = strdup(nconf->an_protoname);
		if (!a->r_nc_netid || !a->r_nc_protofmly || !a->r_nc_proto) {
			if (a->r_nc_netid) {
				free(a->r_nc_netid);
				a->r_nc_netid = NULL;
			}
			if (a->r_nc_protofmly) {
				free(a->r_nc_protofmly);
				a->r_nc_protofmly = NULL;
			}
			if (a->r_nc_proto) {
				free(a->r_nc_proto);
				a->r_nc_proto = NULL;
			}
			free(maddr);
			maddr = NULL;
			free(rp);
			goto fail;
		}
		rp->rpcb_entry_next = NULL;
		if (rlist == NULL) {
			rlist = rp;
		} else {
			tail->rpcb_entry_next = rp;
		}
		tail = rp;
		rp = NULL;
	    }
	}
#ifdef RPCBIND_DEBUG
	if (debugging) {
		for (rp = rlist; rp; rp = rp->rpcb_entry_next) {
			fprintf(stderr, "\t%s %s\n", 
				rp->rpcb_entry_map.r_maddr,
				rp->rpcb_entry_map.r_nc_proto);
		}
	}
#endif
	/*
	 * XXX: getaddrlist info is also being stuffed into getaddr.
	 * Perhaps wrong, but better than it not getting counted at all.
	 */
	rpcbs_getaddr(RPCBVERS4 - 2, prog, vers, netid, maddr);
	*result = rlist;
	return TRUE;

fail:	
	axdr_free((axdrproc_t)&axdr_rpcb_entry_list_ptr, &rlist);
	return FALSE;
}


/* ARGSUSED */
static bool_t
rpcbproc_dump_4_local(void *dummy, rpcblist_ptr *ptr, ar_svc_req_t *rqstp)
{
	int err;

	rpcbs_procinfo(RPCBVERS_4_STAT, RPCBPROC_DUMP);

	if (!check_access(rqstp, NULL, RPCBVERS4)) {
		ar_svcflgerr_weakauth(rqstp);
		return FALSE;
	}

#ifdef RPCBIND_DEBUG
	if (debugging) {
		fprintf(stderr, "RPCBPROC_DUMP\n");
	}
#endif
	err = rpcbproc_copy_rpcb_list(list_rbl, ptr);
	if (err != 0) {
		return FALSE;
	} else {
		return TRUE;
	}
}
