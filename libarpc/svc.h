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
 * svc.h, Server-side remote procedure call interface.
 *
 * Copyright (C) 1986-1993 by Sun Microsystems, Inc.
 */

#ifndef _LIBARPC_RPC_SVC_H
#define _LIBARPC_RPC_SVC_H

#include <sys/cdefs.h>

/*
 * This interface must manage two items concerning remote procedure calling:
 *
 * 1) An arbitrary number of transport connections upon which rpc requests
 * are received.  The two most notable transports are TCP and UDP;  they are
 * created and registered by routines in svc_tcp.c and svc_udp.c, respectively;
 * they in turn call xprt_register and xprt_unregister.
 *
 * 2) An arbitrary number of locally registered services.  Services are
 * described by the following four data: program number, version number,
 * "service dispatch" function, a transport handle, and a boolean that
 * indicates whether or not the exported program should be registered with a
 * local binder service;  if true the program's number and version and the
 * port number from the transport handle are registered with the binder.
 * These data are registered with the rpc svc system via svc_register.
 *
 * A service's dispatch function is called whenever an rpc request comes in
 * on a transport.  The request's program and version numbers must match
 * those of the registered service.  The dispatch function is passed two
 * parameters, struct svc_req * and SVCXPRT *, defined below.
 */

/*
 *      Service control requests
 */
#define AR_SVCGET_VERSQUIET	1
#define AR_SVCSET_VERSQUIET	2
#define AR_SVCGET_CONNMAXREC	3
#define AR_SVCSET_CONNMAXREC	4
#define AR_SVCSET_DEBUG		5
#define AR_SVCGET_REMOTE_ADDR	6	/* remote address (netbuf) */
#define AR_SVCGET_LOCAL_ADDR	7	/* local address (netbuf) */
#define AR_SVCGET_FD		8	/* get fd value */
#define AR_SVCGET_MAXCONNS	9	/* maximum number of connections */
#define AR_SVCSET_MAXCONNS	10	/* maximum number of connections */
#define AR_SVCGET_NETID		11	/* returns ptr to priv netid str */
#define AR_SVCGET_PEERCRED	12	/* get remote ucred, if available */

typedef struct ar_svc_attr_s	ar_svc_attr_t;
typedef struct ar_svc_req_s ar_svc_req_t;
typedef struct ar_svc_xprt_s ar_svc_xprt_t;
typedef struct ar_xprt_debug_s ar_xprt_debug_t;

typedef int (*ar_svc_acceptcb_t)(ar_ioctx_t, ar_svc_xprt_t *, void *);
typedef void (*ar_svc_errorcb_t)(ar_ioctx_t, ar_svc_xprt_t *, 
				 void *, int error);

struct ar_xprt_debug_s {
	FILE		*fout;
	const char 	*prefix;
};

struct ar_svc_attr_s {
	uint32_t		sa_flags;
	int 			sa_sendsz;
	int 			sa_recvsz;
	bool_t			sa_dg_cache;
	ar_svc_acceptcb_t	sa_accept_cb;
	void 			*sa_accept_arg;
	ar_svc_errorcb_t	sa_error_cb;
	void 			*sa_error_arg;
	struct timespec		sa_create_tmout;
	FILE			*sa_debug_file;
	const char		*sa_debug_prefix;
	int			sa_max_connections;
	const char		*sa_pkcs12_passwd;
	uint8_t			*sa_pkcs12;
	uint32_t		sa_pkcs12_len;
	void                    *sa_tls_arg;
	ar_tls_setup_cb_t	sa_tls_setup_cb;
	ar_tls_verify_cb_t	sa_tls_verify_cb;
	ar_tls_info_cb_t	sa_tls_info_cb;
};

/*
 * Service request
 */
struct ar_svc_req_s {
	u_int32_t	rq_xid;		/* transaction id number */
	u_int32_t	rq_prog;	/* service program number */
	u_int32_t	rq_vers;	/* service protocol version */
	u_int32_t	rq_proc;	/* the desired procedure */
	ar_opaque_auth_t rq_cred;	/* raw creds from the wire */
	void		*rq_clntcred;	/* read only cooked cred */
	ar_svc_xprt_t	*rq_xprt;	/* associated transport */
	arpc_err_t	rq_err;		/* rpc level error result */
};

typedef int (*ar_svc_handler_fn_t)(void *, void *, ar_svc_req_t *);
typedef void (*ar_svc_lookup_fn_t)(u_int32_t, ar_svc_handler_fn_t *, 
				   axdrproc_t *, axdrproc_t *, int *, int *);

struct ar_svc_call_obj_s;
typedef struct ar_svc_call_obj_s *ar_svc_call_obj_t;

/*
 * When the service routine is called, it must first check to see if it
 * knows about the procedure;  if not, it should call svcerr_noproc
 * and return.  If so, it should deserialize its arguments via
 * SVC_GETARGS (defined above).  If the deserialization does not work,
 * svcerr_decode should be called followed by a return.  Successful
 * decoding of the arguments should be followed the execution of the
 * procedure's code and a call to svc_sendreply.
 *
 * Also, if the service refuses to execute the procedure due to too-
 * weak authentication parameters, svcerr_weakauth should be called.
 * Note: do not confuse access-control failure with weak authentication!
 *
 * NB: In pure implementations of rpc, the caller always waits for a reply
 * msg.  This message is sent when svc_sendreply is called.
 * Therefore pure service implementations should always call
 * svc_sendreply even if the function logically returns void;  use
 * xdr.h - xdr_void for the xdr routine.  HOWEVER, tcp based rpc allows
 * for the abuse of pure rpc via batched calling or pipelining.  In the
 * case of a batched call, svc_sendreply should NOT be called since
 * this would send a return message, which is what batching tries to avoid.
 * It is the service/protocol writer's responsibility to know which calls are
 * batched and which are not.  Warning: responding to batch calls may
 * deadlock the caller and server processes!
 */

__BEGIN_DECLS
extern int	ar_svc_async(ar_svc_req_t *, ar_svc_call_obj_t *);
extern void	ar_svc_async_done(ar_svc_call_obj_t, bool_t result);
extern int	ar_svc_async_get_resultptr(ar_svc_call_obj_t, void **);
__END_DECLS

/*
 * Lowest level dispatching -OR- who owns this process anyway.
 * Somebody has to wait for incoming requests and then call the correct
 * service routine.  The routine svc_run does infinite waiting; i.e.,
 * svc_run never returns.
 * Since another (co-existant) package may wish to selectively wait for
 * incoming calls or other events outside of the rpc architecture, the
 * routine svc_getreq is provided.  It must be passed readfds, the
 * "in-place" results of a select system call (see select, section 2).
 */

/*
 * a small program implemented by the svc_rpc implementation itself;
 * also see clnt.h for protocol numbers.
 */
__BEGIN_DECLS
extern void ar_rpctest_service(void);
__END_DECLS

/*
 * Socket to use on svcxxx_create call to get default socket
 */
#define	AR_RPC_ANYSOCK	-1
#define AR_RPC_ANYFD	AR_RPC_ANYSOCK

/*
 * These are the existing service side transport implementations
 */

__BEGIN_DECLS
/*
 * Transport independent svc_create routine.
 */
/*
 *      void (*dispatch)();             -- dispatch routine
 *      const arpcprog_t prognum;        -- program number
 *      const arpcvers_t versnum;        -- version number
 *      const char *nettype;            -- network type
 */

extern int ar_svc_attr_init(ar_svc_attr_t *attr);
extern int ar_svc_attr_set_pkcs12(ar_svc_attr_t *attr, const char *passwd,
				  uint8_t *pkcs12, uint32_t len);
extern int ar_svc_attr_set_recvsize(ar_svc_attr_t *attr, int recvsize);
extern int ar_svc_attr_set_sendsize(ar_svc_attr_t *attr, int sendsize);
extern int ar_svc_attr_set_accept_cb(ar_svc_attr_t *attr,
				     ar_svc_acceptcb_t cb, void *arg);
extern int ar_svc_attr_set_debug(ar_svc_attr_t *attr, FILE *fp, 
				 const char *prefix);
extern int ar_svc_attr_set_max_connections(ar_svc_attr_t *attr, int max);
extern int ar_svc_attr_set_create_timeout(ar_svc_attr_t *attr,
				       const struct timespec *);
extern int ar_svc_attr_set_error_cb(ar_svc_attr_t *attr, 
				    ar_svc_errorcb_t cb, void *arg);
extern int ar_svc_attr_set_tls(ar_svc_attr_t *attr, void *arg, 
			       ar_tls_setup_cb_t, ar_tls_verify_cb_t,
			       ar_tls_info_cb_t);

extern int ar_svc_attr_destroy(ar_svc_attr_t *attr);

/*
 * register services for use connections in this contxt.  No port is 
 * opened, nor binding made.
 */
extern int ar_svc_reg(ar_svc_xprt_t *, ar_svc_lookup_fn_t, 
		      const arpcprog_t, const arpcvers_t);
extern int ar_svc_unreg(ar_svc_xprt_t *, ar_svc_lookup_fn_t, 
			const arpcprog_t, const arpcvers_t);
extern int ar_svc_io_reg(ar_ioctx_t ctx, ar_svc_lookup_fn_t lookup,
			const arpcprog_t prog, const arpcvers_t ver);
extern int ar_svc_io_unreg(ar_ioctx_t ctx, ar_svc_lookup_fn_t lookup,
			const arpcprog_t prog, const arpcvers_t ver);

extern int ar_svc_tli_create(ar_ioctx_t, const char *netid, 
			     const arpc_addr_t *, ar_svc_attr_t *, 
			     arpc_err_t *errp, ar_svc_xprt_t **retp);

/*
 * 	ar_ioctx_t ctx;		-- eventing layer
 *      void (*dispatch)();             -- dispatch routine
 *      const arpcprog_t prognum;        -- program number
 *      const arpcvers_t versnum;        -- version number
 */

/*
 * IO connectionful create routine.
 */
extern int ar_svc_vc_create(ar_ioctx_t, ar_vcd_t, void *, 
			    ar_svc_attr_t *, arpc_err_t *, ar_svc_xprt_t **);
/*
 *	ar_ioctx_t ioctx;		-- dispatch context object.
 *	rpc_vcd_t vcd;			-- vc endpoint driver.
 * 	void *vcd_stream		-- vcd handle for listener object.
 *	ar_svc_attr_t *attr		-- attributes for setup.
 *	ar_svc_xprt_t **svcp;			-- return svc context.
 */

/*
 * IO connectionless create routine.
 */
extern int ar_svc_dg_create(ar_ioctx_t, int fd, 
			    ar_svc_attr_t *, arpc_err_t *, ar_svc_xprt_t **);
/*
 *	ar_ioctx_t ioctx;		-- dispatch context object.
 *	int fd;				-- dg socket
 *	ar_svc_attr_t *attr		-- attributes for setup.
 *	ar_svc_xprt_t **svcp;			-- return svc context.
 */

/*
 * Attach a client context to a server endpoint.
 */
struct ar_clnt_attr_s;
struct ar_client_s;
extern int ar_svc_clnt_attach(ar_svc_xprt_t *xprt, const arpcprog_t,
			      const arpcvers_t, struct ar_clnt_attr_s *attr, 
			      arpc_err_t *errp, struct ar_client_s **retp);

/*
 * svc_dg_enable_cache() enables the cache on dg transports.
 */
int ar_svc_dg_enablecache(ar_svc_xprt_t *, const u_int);

void ar_svc_destroy(ar_svc_xprt_t *xprt);
bool_t ar_svc_control(ar_svc_xprt_t *xprt, const u_int cmd, void *info);

void ar_svc_set_user(ar_svc_xprt_t *xprt, void *);
void *ar_svc_get_user(ar_svc_xprt_t *xprt);

arpc_addr_t *ar_svc_getrpccaller(ar_svc_xprt_t *xprt);

extern void	ar_svcflgerr_decode(ar_svc_req_t *);
extern void	ar_svcflgerr_weakauth(ar_svc_req_t *);
extern void	ar_svcflgerr_noproc(ar_svc_req_t *);
extern void	ar_svcflgerr_progvers(ar_svc_req_t *, arpcvers_t, arpcvers_t);
extern void	ar_svcflgerr_auth(ar_svc_req_t *, ar_auth_stat_t);
extern void	ar_svcflgerr_noprog(ar_svc_req_t *);
extern void	ar_svcflgerr_systemerr(ar_svc_req_t *);

extern void	ar_scoflgerr_decode(ar_svc_call_obj_t);
extern void	ar_scoflgerr_weakauth(ar_svc_call_obj_t);
extern void	ar_scoflgerr_noproc(ar_svc_call_obj_t);
extern void	ar_scoflgerr_progvers(ar_svc_call_obj_t, 
				      arpcvers_t, arpcvers_t);
extern void	ar_scoflgerr_auth(ar_svc_call_obj_t, ar_auth_stat_t);
extern void	ar_scoflgerr_noprog(ar_svc_call_obj_t);
extern void	ar_scoflgerr_systemerr(ar_svc_call_obj_t);

__END_DECLS


#endif /* !_LIBARPC_RPC_SVC_H */

