/*	$NetBSD: rpcbind.h,v 1.1 2000/06/03 00:47:21 fvdl Exp $	*/
/*	$FreeBSD: src/usr.sbin/rpcbind/rpcbind.h,v 1.2 2002/10/07 02:56:59 alfred Exp $ */

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

/* #ident	"@(#)rpcbind.h 1.4 90/04/12 SMI" */

/*
 * rpcbind.h
 * The common header declarations
 */

#ifndef _RPCBIND_H_
#define	_RPCBIND_H_ 1

#include "pmap_prot.h"
#include "rpcb_prot.h"

/*
 * Stuff for the rmtcall service
 */
struct encap_parms {
	u_int32_t arglen;
	char *args;
};

typedef struct r_rmtcall_args_s {
	int     rmt_localvers;  /* whether to send port # or uaddr */
	char    *rmt_uaddr;
	char	*rmt_ret;
	u_int	rmt_retlen;
} r_rmtcall_args_t;

extern int debugging;
extern int doabort;
extern int verboselog;
extern int insecure;
extern int oldstyle_local;
extern rpcblist_ptr list_rbl;	/* A list of version 3 & 4 rpcbind services */

extern ar_pmaplist_t *list_pml; /* A list of version 2 rpcbind services */
extern char *udptrans;		/* Name of UDP transport */
extern char *tcptrans;		/* Name of TCP transport */
extern char *udp_uaddr;		/* Universal UDP address */
extern char *tcp_uaddr;		/* Universal TCP address */
extern ar_ioctx_t rpcbind_ioctx;

int add_bndlist(ar_netid_t *);
bool_t is_bound(const char *, const char *);
char *mergeaddr(ar_svc_xprt_t *, const char *, 
		     const char *, const char *);
ar_netid_t *rpcbind_get_conf(const char *);

axdr_ret_t axdr_rmtcall_result(axdr_state_t *xdrs, r_rmtcall_args_t *cap);

void rpcbs_init(void); 
void rpcbs_procinfo(arpcvers_t, arpcproc_t);
void rpcbs_set(arpcvers_t, bool_t);
void rpcbs_unset(arpcvers_t, bool_t);
void rpcbs_getaddr(arpcvers_t, arpcprog_t, arpcvers_t, 
			const char *, const char *);
void rpcbs_rmtcall(arpcvers_t, arpcproc_t, arpcprog_t, 
			arpcvers_t, arpcproc_t, const char *, rpcblist_ptr);

bool_t rpcbproc_getstat(void *argp, rpcb_stat_byvers *result,
			ar_svc_req_t *rqstp, arpcvers_t vers);

void rpcbprog_4_lookup(u_int32_t proc, ar_svc_handler_fn_t *handler, 
		       axdrproc_t * inproc, axdrproc_t * outproc, int * inlen,
		       int * outlen);
void rpcbprog_3_lookup(u_int32_t proc, ar_svc_handler_fn_t *handler, 
		       axdrproc_t * inproc, axdrproc_t * outproc, int * inlen,
		       int * outlen);

/* Common functions shared between versions */
bool_t rpcbproc_set_com(rpcb *argp, bool_t *result, ar_svc_req_t *rqstp,
			arpcvers_t vers);
bool_t rpcbproc_unset_com(rpcb *argp, bool_t *result, ar_svc_req_t *rqstp, 
			  arpcvers_t vers);
bool_t map_set(RPCB *, const char *);
bool_t map_unset(RPCB *, const char *);
void delete_prog(unsigned int);
bool_t rpcbproc_getaddr_com(rpcb *regp, char **result,
			    ar_svc_req_t *rqstp, arpcvers_t, arpcvers_t);
bool_t rpcbproc_gettime_com(void *argp, u_int *result, 
			    ar_svc_req_t *rqstp, arpcvers_t);
bool_t rpcbproc_uaddr2taddr_com(char **argp, arpc_addr_t *result,
				ar_svc_req_t *rqstp, arpcvers_t vers);
bool_t rpcbproc_taddr2uaddr_com(arpc_addr_t  *argp, char **result, 
				ar_svc_req_t *rqstp, arpcvers_t vers);
int create_rmtcall_fd(ar_netid_t *);
bool_t rpcbproc_callit_com(rpcb_rmtcallargs *argp, void *result, 
			   ar_svc_req_t *rqstp, arpcvers_t vers);
void rpcbind_abort(void);
void reap(int);
void toggle_verboselog(int);

int check_access(ar_svc_req_t *, void *args, unsigned int);
int check_callit(ar_svc_req_t *, rpcb_rmtcallargs *, int);
void logit(int, struct sockaddr *, socklen_t, arpcproc_t,
	   arpcprog_t, const char *);
int is_loopback(arpc_addr_t *);

void pmap_lookup(u_int32_t proc, ar_svc_handler_fn_t *handler, 
		       axdrproc_t * inproc, axdrproc_t * outproc, int * inlen,
		       int * outlen);

void write_warmstart(void);
void read_warmstart(void);

char *addrmerge(arpc_addr_t *caller, const char *serv_uaddr, 
		     const char *clnt_uaddr, const char *netid);
void network_init(void);
struct sockaddr *local_sa(int, u_int *lenp);

char *rqst2uaddr(ar_svc_req_t *rqstp);
int  rpcbproc_copy_rpcb_list(rpcblist *orig, rpcblist **newp);


/* For different getaddr semantics */
#define	RPCB_ALLVERS 0
#define	RPCB_ONEVERS 1

#endif /* !_RPCBIND_H_ */
