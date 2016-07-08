/*
 * Copyright (C) 2010  Pace Plc
 * All Rights Reserved.
 *
 * Copyright (c) 2009, Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Sun Microsystems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * clnt.h - Client side remote procedure call interface.
 *
 * Copyright (c) 1986-1991,1994-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _LIBARPC_CLNT_H_
#define _LIBARPC_CLNT_H_

#include <libarpc/stat.h>
#include <sys/cdefs.h>
#include <sys/un.h>

typedef struct ar_clnt_attr_s ar_clnt_attr_t;
typedef struct ar_client_s ar_client_t;
typedef struct ar_clnt_debug_s ar_clnt_debug_t;
/*
 * Well-known IPV6 RPC broadcast address.
 */
#define AR_RPCB_MULTICAST_ADDR "ff02::202"

/*
 * the following errors are in general unrecoverable.  The caller
 * should give up rather than retry.
 */
#define AR_IS_UNRECOVERABLE_RPC(s) (((s) == ARPC_AUTHERROR) || \
	((s) == ARPC_CANTENCODEARGS) || \
	((s) == ARPC_CANTDECODERES) || \
	((s) == ARPC_VERSMISMATCH) || \
	((s) == ARPC_PROCUNAVAIL) || \
	((s) == ARPC_PROGUNAVAIL) || \
	((s) == ARPC_PROGVERSMISMATCH) || \
	((s) == ARPC_CANTDECODEARGS))

/*
 * Timers used for the pseudo-transport protocol when using datagrams
 */
struct arpc_timers_s {
	u_short		rt_srtt;	/* smoothed round-trip time */
	u_short		rt_deviate;	/* estimated deviation */
	u_long		rt_rtxcur;	/* current (backed-off) rto */
};

struct ar_clnt_call_obj_s;
typedef struct ar_clnt_call_obj_s *ar_clnt_call_obj_t;
typedef void (*ar_clnt_async_cb_t)(ar_clnt_call_obj_t, void *arg, 
				   const arpc_err_t *stat, void *result);

typedef void (*ar_conn_cb_t)(ar_client_t *clnt, void *arg, 
			     const arpc_createerr_t *errp);
typedef void (*ar_discon_cb_t)(ar_client_t *clnt, void *arg, 
			       const arpc_err_t *errp);

struct ssl_ctx_st;
struct x509_store_ctx_st;
struct ssl_st;

struct ar_clnt_attr_s {
	uint32_t		ca_flags;
	int 			ca_sendsz;
	int 			ca_recvsz;
	arpcvers_t		ca_minver;
	arpcvers_t		ca_maxver;
	struct timespec 	ca_create_tmout;
	void			*ca_svc_user;
	ar_conn_cb_t		ca_conn_cb;
	void			*ca_conn_arg;
	ar_discon_cb_t		ca_discon_cb;
	void			*ca_discon_arg;
	FILE			*ca_debug_file;
	const char		*ca_pkcs12_passwd;
	uint8_t			*ca_pkcs12;
	uint32_t		ca_pkcs12_len;
	const char		*ca_debug_prefix;
	void                    *ca_tls_arg;
	ar_tls_setup_cb_t	ca_tls_setup_cb;
	ar_tls_verify_cb_t	ca_tls_verify_cb;
	ar_tls_info_cb_t	ca_tls_info_cb;
};

#define CA_FLG_ALLOW_SVC	0x00000001
#define CA_FLG_REQUIRED		0x00000002


/*      
 * Feedback values used for possible congestion and rate control
 */
#define AR_FEEDBACK_REXMIT1	1	/* first retransmit */
#define AR_FEEDBACK_OK		2	/* no retransmits */    

/* Used to set version of portmapper used in broadcast */
  
#define AR_CLCR_SET_LOWVERS	3
#define AR_CLCR_GET_LOWVERS	4
 
#define AR_RPCSMALLMSGSIZE 400	/* a more reasonable packet size */

/*
 * client side rpc interface ops
 *
 * Parameter types are:
 *
 */

/*
 * control operations that apply to both udp and tcp transports
 */
#define AR_CLSET_TIMEOUT	1	/* set timeout (timeval) */
#define AR_CLGET_TIMEOUT	2	/* get timeout (timeval) */
#define AR_CLGET_SERVER_ADDR	3	/* get server's address (netbuf) */
#define AR_CLGET_FD		6	/* get connections file descriptor */
#define AR_CLGET_SVC_ADDR	7	/* get server's address (netbuf ptr) */
#define AR_CLSET_FD_CLOSE	8	/* close fd while clnt_destroy */
#define AR_CLSET_FD_NCLOSE	9	/* Do not close fd while clnt_destroy */
#define AR_CLGET_XID 		10	/* Get xid */
#define AR_CLSET_XID		11	/* Set xid */
#define AR_CLGET_VERS		12	/* Get version number */
#define AR_CLSET_VERS		13	/* Set version number */
#define AR_CLGET_PROG		14	/* Get program number */
#define AR_CLSET_PROG		15	/* Set program number */
#define AR_CLSET_SVC_ADDR	16	/* get server's address (netbuf) */
#define AR_CLSET_PUSH_TIMOD	17	/* push timod if not already present */
#define AR_CLSET_POP_TIMOD	18	/* pop timod */
/*
 * Connectionless only control operations
 */
#define AR_CLSET_RETRY_TIMEOUT 	4   /* set retry timeout (timeval) */
#define AR_CLGET_RETRY_TIMEOUT 	5   /* get retry timeout (timeval) */
#define AR_CLSET_ASYNC		19
#define AR_CLSET_CONNECT	20	/* Use connect() for UDP. (int) */
#define AR_CLSET_RETRY_COUNT	21	
#define AR_CLGET_RETRY_COUNT	22	

#define AR_CLSET_RETRY_TIMEOUT_SPEC	23
#define AR_CLGET_RETRY_TIMEOUT_SPEC	24

/* new control requests: */
#define AR_CLSET_TIMEOUT_SPEC	25
#define AR_CLGET_TIMEOUT_SPEC	26
#define AR_CLGET_CONNECTED	27
#define AR_CLSET_DEBUG		28
#define AR_CLGET_LOCAL_ADDR	29	/* get local addr (netbuf) */
#define AR_CLGET_PEERCRED	30	/* get peer credentials (ucred) */

struct ar_clnt_debug_s {
	FILE		*fout;
	const char 	*prefix;
};

/*
 * RPCTEST is a test program which is accessible on every rpc
 * transport/port.  It is used for testing, performance evaluation,
 * and network administration.
 */

#define ARPCTEST_PROGRAM		((arpcprog_t)1)
#define ARPCTEST_VERSION		((arpcvers_t)1)
#define ARPCTEST_NULL_PROC		((arpcproc_t)2)
#define ARPCTEST_NULL_BATCH_PROC	((arpcproc_t)3)

/*
 * By convention, procedure 0 takes null arguments and returns them
 */

#define AR_NULLPROC ((arpcproc_t)0)

/*
 * Below are the client handle creation routines for the various
 * implementations of client side rpc.  They can return NULL if a
 * creation failure occurs.
 */
__BEGIN_DECLS
extern int ar_clnt_attr_init(ar_clnt_attr_t *attr);
extern int ar_clnt_attr_set_pkcs12(ar_clnt_attr_t *attr, const char *passwd,
				   uint8_t *pkcs12, uint32_t len);
extern int ar_clnt_attr_set_recvsize(ar_clnt_attr_t *attr, int recvsize);
extern int ar_clnt_attr_set_sendsize(ar_clnt_attr_t *attr, int sendsize);
extern int ar_clnt_attr_set_minver(ar_clnt_attr_t *attr, arpcvers_t);
extern int ar_clnt_attr_set_maxver(ar_clnt_attr_t *attr, arpcvers_t);
extern int ar_clnt_attr_set_create_timeout(ar_clnt_attr_t *attr, 
					   const struct timespec *);
extern int ar_clnt_attr_set_svc(ar_clnt_attr_t *attr, bool_t, void *);
extern int ar_clnt_attr_set_conncb(ar_clnt_attr_t *attr,
				   ar_conn_cb_t, void *);
extern int ar_clnt_attr_set_disconcb(ar_clnt_attr_t *attr,
				  ar_discon_cb_t, void *);
extern int ar_clnt_attr_set_required(ar_clnt_attr_t *attr, bool_t required);
extern int ar_clnt_attr_set_debug(ar_clnt_attr_t *attr, FILE *fp, 
			       const char *prefix);
extern int ar_clnt_attr_set_tls(ar_clnt_attr_t *attr, void *arg, 
				ar_tls_setup_cb_t, ar_tls_verify_cb_t,
				ar_tls_info_cb_t);
extern int ar_clnt_attr_destroy(ar_clnt_attr_t *attr);


/*
 * Generic client creation routine.
 */
extern int ar_clnt_create(ar_ioctx_t, const char *, const arpcprog_t,
			  const arpcvers_t, const char *, ar_clnt_attr_t *,
			  arpc_createerr_t *errp, ar_client_t **retp);
/*
 *
 *	ar_ioctx_t				-- ioctx (eventing/async)
 * 	const char *hostname;			-- hostname
 *	const rpcprog_t prog;			-- program number
 *	const rpcvers_t vers;			-- version number
 *	const char *nettype;			-- network type
 *	ar_clnt_attr_t;			-- additonal options
 *	ar_client_t **retp;				-- resulting client
 */


extern int ar_clnt_tli_create(ar_ioctx_t, const char *netid, 
			      const arpc_addr_t *, const arpcprog_t, 
			      const arpcvers_t, ar_clnt_attr_t *attr,
			      arpc_createerr_t *errp, ar_client_t **retp);

/*
 * Low level clnt async routine for connectionful transports, e.g. tcp.
 */
extern int ar_clnt_ioep_vc_create(ar_ioep_t ep, const arpcprog_t, 
				  const arpcvers_t, arpc_createerr_t *errp,
				  ar_client_t **retp);
/*
 *	ar_ioep_t ep;		-- io system vcd async endpoint
 *	const u_long prog;	-- program number
 *	const u_long vers;	-- version number
 * 	ar_client_t **retp;		-- returned client context
 */


/*
 *	const int fd;				-- open file descriptor
 *	const struct netbuf *svcaddr;		-- servers address
 *	const rpcprog_t program;		-- program number
 *	const rpcvers_t version;		-- version number
 *	const u_int sendsz;			-- buffer recv size
 *	const u_int recvsz;			-- buffer send size
 */

extern int ar_clnt_vc_create(ar_ioctx_t, ar_vcd_t drv, const arpc_addr_t *,
			     const arpcprog_t, const arpcvers_t, 
			     ar_clnt_attr_t *attr, arpc_createerr_t *errp,
			     ar_client_t **retp);

extern int ar_clnt_dg_create(ar_ioctx_t, const arpc_addr_t *,
			     const arpcprog_t, const arpcvers_t, 
			     ar_clnt_attr_t *attr, arpc_createerr_t *errp,
			     ar_client_t **retp);

__END_DECLS


/*
 * The asynchronous interface:
 * 
 * int 
 * clnt_call_async_copy(ar_client_t *rh, rpcproc_t proc, axdrproc_t xargs, 
 * 			void *argsp, axdrproc_t xres, int ressize,
 *			ar_clnt_async_cb_t cb, void *arg, 
 * 			ar_clnt_call_obj_t *handlep);
 *
 * int 
 * clnt_call_async_inplace(ar_client_t *rh, rpcproc_t proc, 
 *			axdrproc_t xargs, void *argsp, axdrproc_t xres, 
 * 			int ressize, ar_clnt_async_cb_t cb, void *arg, 
 * 			ar_clnt_call_obj_t *handlep);
 * 
 * void clnt_call_cancel(ar_clnt_call_obj_t handle);
 * 
 */
__BEGIN_DECLS
extern int ar_clnt_call_async_copy(ar_client_t *, arpcproc_t, axdrproc_t,
				   void *, axdrproc_t, int, 
				   ar_clnt_async_cb_t, void *,
				   struct timespec *, ar_clnt_call_obj_t *);

extern int ar_clnt_call_async_inplace(ar_client_t *, arpcproc_t, axdrproc_t, 
				      void *, axdrproc_t, int, 
				      ar_clnt_async_cb_t, void *, 
				      struct timespec *, ar_clnt_call_obj_t *);
extern void ar_clnt_call_cancel(ar_clnt_call_obj_t);

extern int ar_clnt_call_geterr(ar_clnt_call_obj_t, arpc_err_t *);
__END_DECLS

/*
 * RPC broadcast interface
 * The call is broadcasted to all locally connected nets.
 *
 * extern enum clnt_stat
 * rpc_broadcast(prog, vers, proc, xargs, argsp, xresults, resultsp,
 *			eachresult, nettype)
 *	const rpcprog_t		prog;		-- program number
 *	const arpcvers_t		vers;		-- version number
 *	const rpcproc_t		proc;		-- procedure number
 *	const axdrproc_t	xargs;		-- xdr routine for args
 *	caddr_t		argsp;		-- pointer to args
 *	const axdrproc_t	xresults;	-- xdr routine for results
 *	caddr_t		resultsp;	-- pointer to results
 *	const resultproc_t	eachresult;	-- call with each result
 *	const char		*nettype;	-- Transport type
 *
 * For each valid response received, the procedure eachresult is called.
 * Its form is:
 *		done = eachresult(resp, raddr, nconf)
 *			bool_t done;
 *			caddr_t resp;
 *			struct netbuf *raddr;
 *			struct netconfig *nconf;
 * where resp points to the results of the call and raddr is the
 * address if the responder to the broadcast.  nconf is the transport
 * on which the response was received.
 *
 * extern enum clnt_stat
 * rpc_broadcast_exp(prog, vers, proc, xargs, argsp, xresults, resultsp,
 *			eachresult, inittime, waittime, nettype)
 *	const rpcprog_t		prog;		-- program number
 *	const arpcvers_t		vers;		-- version number
 *	const rpcproc_t		proc;		-- procedure number
 *	const axdrproc_t	xargs;		-- xdr routine for args
 *	caddr_t		argsp;		-- pointer to args
 *	const axdrproc_t	xresults;	-- xdr routine for results
 *	caddr_t		resultsp;	-- pointer to results
 *	const resultproc_t	eachresult;	-- call with each result
 *	const int 		inittime;	-- how long to wait initially
 *	const int 		waittime;	-- maximum time to wait
 *	const char		*nettype;	-- Transport type
 */

typedef bool_t (*aresultproc_t)(caddr_t, ...);

__BEGIN_DECLS
extern ar_stat_t ar_clnt_call(ar_client_t *rh, arpcproc_t proc, 
			      axdrproc_t xargs, void *argsp, 
			      axdrproc_t xres, void *resp, int resplen, 
			      struct timespec *timeout, arpc_err_t *errp);
extern bool_t ar_clnt_control(ar_client_t *rh, u_int req, void *info);

extern void ar_clnt_destroy(ar_client_t *);

__END_DECLS

#endif /* !_LIBARPC_CLNT_H_ */

