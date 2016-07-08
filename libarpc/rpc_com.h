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
 * Copyright (c) 1986 - 1991 by Sun Microsystems, Inc.
 */

/*
 * rpc_com.h, Common definitions for both the server and client side.
 * All for the topmost layer of rpc
 *
 * In Sun's tirpc distribution, this was installed as <rpc/rpc_com.h>,
 * but as it contains only non-exported interfaces, it was moved here.
 */

#ifndef _RPC_RPCCOM_H
#define	_RPC_RPCCOM_H

#include <sys/cdefs.h>
#include <sys/queue.h>
#ifdef HAVE_LIBEVENT
#include <event.h>
#endif

/*
 * The max size of the transport, if the size cannot be determined
 * by other means.
 */
#define	RPC_MAXDATASIZE 9000
#define	RPC_MAXADDRSIZE 1024

#ifndef EOK
#define EOK 0
#endif

struct ar_ioep_s;
struct ar_ioctx_s;
struct svc_callout;
struct ar_xid_state_s;

typedef TAILQ_HEAD(rpc_clnt_list_s, ar_client_s) rpc_clnt_list_t;
typedef TAILQ_ENTRY(ar_client_s) rpc_clnt_lent_t;
typedef TAILQ_HEAD(cco_list_s, ar_clnt_call_obj_s) cco_list_t;
typedef TAILQ_ENTRY(ar_clnt_call_obj_s) cco_listent_t;
typedef TAILQ_HEAD(cout_list_s, svc_callout) cout_list_t;
typedef TAILQ_ENTRY(svc_callout) cout_listent_t;

typedef int (*clnt_call_t)(ar_client_t *, arpcproc_t, axdrproc_t, void *,
			   bool_t inplace, axdrproc_t, void *, int,
			   ar_clnt_async_cb_t, void *, struct timespec *,
			   ar_clnt_call_obj_t *);
typedef int (*clnt_handoff_t)(ar_client_t *, ar_client_t *, cco_list_t *,
			      struct ar_xid_state_s *xstate,
			      arpc_createerr_t *errp);
typedef void (*clnt_destroy_t)(ar_client_t *);
typedef bool_t (*clnt_control_t)(ar_client_t *, u_int, void *);
typedef int (*clnt_call_cancel_t)(ar_client_t *, ar_clnt_call_obj_t cco);
typedef void (*clnt_call_reauth_t)(ar_client_t *, ar_clnt_call_obj_t cco);
typedef void (*clnt_call_dropref_t)(ar_client_t *, ar_clnt_call_obj_t cco);

struct clnt_ops {
	/* call remote procedure */
	clnt_call_t		cl_call;
	/* destroy this structure */
	clnt_destroy_t		cl_destroy;
	/* the ioctl() of rpc */
	clnt_control_t		cl_control;
	/* general to specific handoff */
	clnt_handoff_t		cl_handoff;
	/* cancel pending call */
	clnt_call_cancel_t	cl_cancel;
	/* restart a call (for auth refresh) */
	clnt_call_reauth_t	cl_reauth;
	/* drop a call reference (for sync) */
	clnt_call_dropref_t	cl_dropref;
};

typedef enum clnt_state_e {
	CLNT_STATE_RESOLVE,
	CLNT_STATE_BIND,
	CLNT_STATE_CONNECT,
	CLNT_STATE_ESTABLISHED
} clnt_state_t;

/*
 * Client rpc handle.
 * Created by individual implementations
 * Client is responsible for initializing auth, see e.g. auth_none.c.
 */
struct ar_client_s {
	rpc_clnt_lent_t		cl_listent;
	int			cl_flags;
	int			cl_refcnt;
	struct clnt_ops		*cl_ops;
	ar_ioep_t		cl_ioep;
	ar_ioctx_t		cl_ioctx;
	arpcprog_t		cl_prog;
	arpcvers_t		cl_ver;
	struct timespec		cl_defwait;
	int			cl_queued_err;
	ar_conn_cb_t		cl_conn_cb;
	void			*cl_conn_cb_arg;
	ar_discon_cb_t		cl_discon_cb;
	void			*cl_discon_cb_arg;
	void			*cl_private;	/* private stuff */
};

#define CLNT_FLG_DESTROY	0x00000001
#define CLNT_FLG_KILL_SVC	0x00000002
#define CLNT_FLG_USRREF_DEC	0x00000004	/* usr reference dropped */
#define CLNT_FLG_DISCON_CALLED	0x00000008

/*
 * void
 * CLNT_ABORT(rh);
 *	ar_client_t *rh;
 */
#define	CLNT_ABORT(rh)	((*(rh)->cl_ops->cl_abort)(rh))
#define	clnt_abort(rh)	((*(rh)->cl_ops->cl_abort)(rh))

/*
 * struct rpc_err
 * CLNT_GETERR(rh);
 *	ar_client_t *rh;
 */
#define	CLNT_GETERR(rh,errp)	((*(rh)->cl_ops->cl_geterr)(rh, errp))
#define	clnt_geterr(rh,errp)	((*(rh)->cl_ops->cl_geterr)(rh, errp))


/*
 * bool_t
 * CLNT_FREERES(rh, xres, resp);
 *	ar_client_t *rh;
 *	xdrproc_t xres;
 *	void *resp;
 */
#define	CLNT_FREERES(rh,xres,resp) ((*(rh)->cl_ops->cl_freeres)(rh,xres,resp))
#define	clnt_freeres(rh,xres,resp) ((*(rh)->cl_ops->cl_freeres)(rh,xres,resp))

/*
 * void
 * CLNT_DESTROY(rh);
 *	ar_client_t *rh;
 */
#define	CLNT_DESTROY(rh)	((*(rh)->cl_ops->cl_destroy)(rh))

/*
 * Little interface for allocating XID's
 */
struct ar_xid_state_s {
	uint32_t	nextxid;
};

struct xp_ops {
	/* send a server call reply (using sco) */
	int	(*xp_sco_reply)(ar_svc_xprt_t *, ar_svc_call_obj_t sco);

	/* alloc a server call tracking structure */
	int	(*xp_sco_alloc)(ar_svc_xprt_t *, ar_svc_call_obj_t *scop);

	/* free a server call tracking structure */
	void	(*xp_sco_destroy)(ar_svc_xprt_t *, ar_svc_call_obj_t sco);

	/* destroy this struct */
	void	(*xp_destroy)(ar_svc_xprt_t *);

	/* catch-all function */
	bool_t  (*xp_control)(ar_svc_xprt_t *, const u_int, void *);
};

/*
 * Server side transport handle
 */
struct ar_svc_xprt_s {
	int			xp_refcnt;
	int			xp_flags;
	const struct xp_ops	*xp_ops;
	ar_ioep_t		xp_ioep;
	char			*xp_netid;	 /* network token */
	ar_ioctx_t		xp_ioctx;
	void			*xp_user;
	int			xp_type;	 /* transport type */
	int			xp_queued_err;
	ar_svc_errorcb_t	xp_error_cb;
	void			*xp_error_arg;
};

#define XP_FLG_DESTROY		0x00000001
#define XP_FLG_USRREF_DEC	0x00000002	/* usr reference dropped */


/*
 *  Approved way of getting address of caller
 */
#define svc_getrpccaller(x) (&(x)->xp_rtaddr)

typedef TAILQ_HEAD(sco_list_s, ar_svc_call_obj_s) sco_list_t;
typedef TAILQ_ENTRY(ar_svc_call_obj_s) sco_listent_t;

typedef enum sco_state_e {
	SCO_STATE_INIT = 1,
	SCO_STATE_GET_ARGS,
	SCO_STATE_CALL,
	SCO_STATE_ASYNC,
	SCO_STATE_SEND_REPLY,
	SCO_STATE_CACHED,
	SCO_STATE_DEAD
} sco_state_t;

struct ar_svc_call_obj_s {
	ar_svc_xprt_t			*sco_xp;
	sco_state_t		sco_state;
	int			sco_refcnt;
	sco_listent_t		sco_listent;
	ar_svc_req_t		sco_req;
	uint32_t		sco_flags;
	ar_svc_handler_fn_t	sco_callback;
	void			*sco_args;
	axdrproc_t		sco_argsxdr;
	int			sco_argslen;
	void			*sco_result;
	axdrproc_t		sco_resultxdr;
	int			sco_resultlen;

	arpc_msg_t		sco_reply;

	void			*sco_lower; /* for ep driver */
	arpc_err_t		sco_err;	/* rpc level error result */
};

#define SCO_FLG_ASYNC		0x00000001
#define SCO_FLG_DESTROY		0x00000002
#define SCO_FLG_USRREF_DEC	0x00000004
#define SCO_FLG_HNDLR_DONE	0x00000008
#define SCO_FLG_UNLINKED	0x00000010


typedef enum cco_state_e {
	CCO_STATE_QUEUED = 1,
	CCO_STATE_PENDING,
	CCO_STATE_RUNNING,
	CCO_STATE_RESULTS,
	CCO_STATE_DONE,
	CCO_STATE_DEAD
} cco_state_t;

typedef enum clnt_args_type_e {
	CLNT_ARGS_TYPE_XDR,
	CLNT_ARGS_TYPE_BUF
} clnt_args_type_t;

struct ar_clnt_call_obj_s {
	ar_client_t			*cco_client;
	cco_state_t		cco_state;
	uint32_t		cco_flags;
	int			cco_refcnt;
	uint32_t		cco_xid;
	cco_listent_t		cco_listent;
	struct timespec		cco_timeout;	/* timeout interval */
	struct timespec		cco_start;	/* time at start */
	clnt_args_type_t	cco_rtype;
	union {
		struct {
			char		*buf;
			int		len;
		}	cco_buffer;
		struct {
			void		*obj;
			axdrproc_t	xdrp;
		}	cco_xdr;
	}			cco_args;
	axdrproc_t		cco_xres;
	int			cco_ressize;
	void			*cco_resp;
	int			cco_authrefresh;
	arpc_err_t		cco_rpc_err;
	arpc_msg_t		cco_call;
	ar_clnt_async_cb_t	cco_cb;
	void			*cco_cb_arg;
	void			*cco_lower; /* for ep driver */
};

#define CCO_FLG_RESULT_ALLOCED	0x00000001
#define CCO_FLG_DESTROY		0x00000002	/* destroy queued */
#define CCO_FLG_USRREF_DROPPED	0x00000004	/* usr reference released */

#define CG_DEF_RPC_TIMEOUT_SECS		30
#define CG_DEF_RPC_TIMEOUT_NSECS	0

#define CG_DEF_CONN_TIMEOUT_SECS	60
#define CG_DEF_CONN_TIMEOUT_NSECS	0

typedef struct ep_driver_s {
	void (*epd_poll_setup)(ar_ioep_t ep, struct pollfd *pfd,
			       int *timeoutp);
	void (*epd_poll_dispatch)(ar_ioep_t ep, struct pollfd *pfd);
	void (*epd_destroy)(ar_ioep_t ep);
	/* send a message (stateless) */
	int (*epd_sendmsg)(ar_ioep_t ep, arpc_msg_t *, ar_svc_call_obj_t);

	int (*epd_add_client)(ar_ioep_t ep, const arpcprog_t, const arpcvers_t,
			      ar_clnt_attr_t *, arpc_err_t *errp,
			      ar_client_t **);
#ifdef HAVE_LIBEVENT
	int (*epd_event_setup)(ar_ioep_t ep, struct event_base *evbase);
#endif
} ep_driver_t;

typedef TAILQ_HEAD(ioep_list_s, ar_ioep_s) ioep_list_t;
typedef TAILQ_ENTRY(ar_ioep_s) ioep_listent_t;

typedef enum ar_ioep_type_e {
	IOEP_TYPE_VC,
	IOEP_TYPE_DG
} ar_ioep_type_t;


struct ar_ioep_s {
	ioep_listent_t		iep_listent;
	ar_ioep_type_t		iep_type;
	int			iep_refcnt;
	uint32_t		iep_flags;
	ep_driver_t		*iep_drv;
	void			*iep_drv_arg;
	ar_ioctx_t		iep_ioctx;
	struct event            *iep_event;
	ar_auth_t		*iep_auth;	/* clnt authenticator */
	ar_opaque_auth_t	iep_verf;	/* svc raw response verifier */
	ar_svc_xprt_t		*iep_svc_ctx;
	ar_clnt_call_obj_t	iep_clnt_reply;
	ar_svc_call_obj_t	iep_svc_call;
	rpc_clnt_list_t		iep_client_list;
	cco_list_t		iep_clnt_calls;
	sco_list_t		iep_svc_async_calls;
	sco_list_t		iep_svc_replies;
	sco_list_t		iep_svc_cache;
	struct ar_xid_state_s	iep_xid_state;
	FILE			*iep_debug_file;
	char			*iep_debug_prefix;
};

#define IEP_FLG_ALLOW_SVC	0x00000001
#define IEP_FLG_DESTROY		0x00000002	/* queued destroy */

extern int ar_ioep_init(ar_ioep_t, ar_ioctx_t, ar_ioep_type_t,
			ep_driver_t *, void *, FILE *, const char *prefix);
extern void ar_ioep_cleanup(ar_ioep_t);

struct ar_vcd_s {
	ar_vcd_readfn_t		vcd_read;
	ar_vcd_writefn_t	vcd_write;
	ar_vcd_closefn_t	vcd_close;
	ar_vcd_closefn_t	vcd_shutdown;
	ar_vcd_cntrlfn_t	vcd_control;
	ar_vcd_psetupfn_t	vcd_poll_setup;
	ar_vcd_pdispatchfn_t	vcd_poll_dispatch;
	ar_vcd_getfdfn_t	vcd_get_fd;
	ar_vcd_fromfd_t		vcd_from_fd;
	ar_vcd_connfn_t		vcd_connect;
	ar_vcd_accept_t		vcd_accept;
	ar_vcd_getladdr_t	vcd_getladdr;
	ar_vcd_getfamily_t	vcd_getfamily;
	ar_vcd_islistener_t	vcd_islistener;
	ar_vcd_listen_t		vcd_listen;
	ar_vcd_init_t		vcd_init;
	ar_vcd_destroy_t	vcd_destroy;
	ar_vcd_gettmout_t	vcd_gettmout;
};

/*
 * The services list
 * Each entry represents a set of procedures (an rpc program).
 * The dispatch routine takes request structs and runs the
 * apropriate procedure.
 * The lookup routine takes the procedure number and returns
 * the information required to run the procedure.
 */
typedef struct svc_callout svc_callout_t;

struct svc_callout {
	cout_listent_t		sc_listent;
	arpcprog_t		sc_prog;
	arpcvers_t		sc_vers;
	char			*sc_netid;
	ar_svc_lookup_fn_t	sc_lookup;
	void			(*sc_dispatch)(ar_svc_req_t *,
					       ar_svc_xprt_t *);
};

typedef TAILQ_HEAD(driver_list_s, driver_map_s) driver_list_t;
typedef TAILQ_ENTRY(driver_map_s) drv_listent_t;
struct driver_map_s {
	drv_listent_t	drv_listent;
	char		drv_proto[16];
	ar_vcd_t	drv_vcd;
};
typedef struct driver_map_s *driver_map_t;

struct ar_ioctx_s {
	ioep_list_t     icx_ep_list;
	cout_list_t     icx_svc_list;
	driver_list_t   icx_drv_list;
	ar_netid_t      *icx_netid_list;
	int             icx_verbose;
};

#define tspecclear(tvp)  (tvp)->tv_sec = (tvp)->tv_nsec = 0
#define tspecisset(tvp)  ((tvp)->tv_sec || (tvp)->tv_nsec)

#define tspeccmp(tvp, uvp, cmp)                                 \
    (((tvp)->tv_sec == (uvp)->tv_sec) ?                         \
	((tvp)->tv_nsec cmp (uvp)->tv_nsec) :                   \
	((tvp)->tv_sec cmp (uvp)->tv_sec))

#define tspecadd(tvp, uvp, vvp)                                 \
    do {                                                        \
	(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;          \
	(vvp)->tv_nsec = (tvp)->tv_nsec + (uvp)->tv_nsec;       \
	if ((vvp)->tv_nsec >= 1000000000) {                     \
	    (vvp)->tv_sec++;                                    \
	    (vvp)->tv_nsec -= 1000000000;                       \
	}                                                       \
    } while (0)

#define tspecsub(tvp, uvp, vvp)                                 \
    do {                                                        \
	(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
	(vvp)->tv_nsec = (tvp)->tv_nsec - (uvp)->tv_nsec;       \
	if ((vvp)->tv_nsec < 0) {                               \
	    (vvp)->tv_sec--;                                    \
	    (vvp)->tv_nsec += 1000000000;                       \
	}                                                       \
    } while (0)

#define RPCTRACE(ioctx, l, fmt...)				\
    do {							\
	    if (ioctx && (ioctx)->icx_verbose >= l) {		\
		    fprintf(stdout, "libarpc CTX %p: ", ioctx);	\
		    fprintf(stdout, ## fmt);			\
	    }							\
    } while (0)

__BEGIN_DECLS

extern void ar_svc_reply_done(ar_svc_call_obj_t);
extern void ar_clnt_call_done(ar_clnt_call_obj_t);
extern ar_svc_call_obj_t ar_svc_new_rx_msg(ar_ioep_t);
extern ar_clnt_call_obj_t ar_clnt_new_rx_msg(ar_ioep_t);
extern axdr_ret_t ar_clnt_handle_reply(axdr_state_t *, ar_ioep_t,
				       arpc_msg_t *, ar_clnt_call_obj_t *ccop);
extern axdr_ret_t ar_svc_handle_call(axdr_state_t *, ar_ioep_t,
				     arpc_msg_t *, ar_svc_call_obj_t *scop);
extern int ar_fixup_addr(arpc_addr_t *, const arpc_addr_t *);

extern void ar_ioep_fatal_error(ar_ioep_t);
extern bool_t ar_time_not_ok(struct timespec *t);
extern int ar_gettime(struct timespec *res);
extern int ar_time_to_ms(struct timespec *now);
extern int ar_tsaddmsecs(struct timespec *now, int msecs);

extern void ar_xid_init(struct ar_xid_state_s *state);
extern uint32_t ar_xid_get(struct ar_xid_state_s *state);
extern void ar_seterr_reply(arpc_msg_t *msg, arpc_err_t *error);
extern int ar_clnt_cco_init(ar_clnt_call_obj_t cco, ar_client_t *cl,
			    ar_auth_t *auth, struct ar_xid_state_s *xids,
			    arpcproc_t proc, axdrproc_t xargs, void *argsp,
			    bool_t inplace, axdrproc_t xres, void *resp,
			    int ressize, ar_clnt_async_cb_t cb, void *cb_arg,
			    struct timespec *tout);
extern void ar_clnt_cco_cleanup(ar_auth_t *auth, ar_clnt_call_obj_t cco);
extern int ar_clnt_cco_reauth(ar_auth_t *auth, ar_clnt_call_obj_t cco);
extern bool_t ar_clnt_control_default(ar_client_t *rh, u_int req, char *info);
extern void ar_svc_sco_cleanup(ar_svc_call_obj_t sco);
extern void ar_svc_sco_unlink(ar_svc_call_obj_t sco);
extern int ar_svc_sco_init(ar_svc_call_obj_t sco, ar_svc_xprt_t *xp);
extern bool_t ar_svc_control_default(ar_svc_xprt_t *xprt,
				     const u_int cmd, void *info);

extern void ar_svcerr_systemerr(ar_svc_xprt_t *, uint32_t,
				ar_svc_call_obj_t sco);

void ar_log_msg(ar_ioep_t, arpc_msg_t *msg, const char *heading);

axdr_ret_t axdr_opaque_auth(axdr_state_t *xdrs, ar_opaque_auth_t *ap);
extern u_int ar_get_t_size(int, int, int);
extern int ar_get_a_size(sa_family_t af, int *sizep);


__END_DECLS

#endif /* _RPC_RPCCOM_H */
