/*
 * Copyright (C) 2010  Pace Plc
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Pace Plc nor the names of its
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
 * rpc_vc.c
 *
 * common code for client/server vc (connection based/TCP) rpc links
 *
 */

#include "compat.h"

#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#ifdef HAVE_LIBEVENT
#include <event.h>
#endif

#include <libarpc/stack.h>
#include <libarpc/arpc.h>
#include "rpc_com.h"

struct vep_async_stack_s {
	astk_t		as_stack;
	uint32_t	as_buf[64];
};

typedef struct vep_async_stack_s vep_as_t;

typedef enum vep_tx_type_e {
	VEP_TX_TYPE_XDR,
	VEP_TX_TYPE_BUF
} vep_tx_type_t;

typedef enum vep_msgtype_e {
	VEP_MSGTYPE_CALL = 1,
	VEP_MSGTYPE_SCO_REPLY,
	VEP_MSGTYPE_SYNC_REPLY,
} vep_msgtype_t;

typedef enum vep_tx_op_e {
	VEP_TX_OP_CALL,
	VEP_TX_OP_REPLY
} vep_tx_op_t;

typedef enum vep_rx_state_e {
	VEP_RX_STATE_SKIPRECORD = 1,
	VEP_RX_STATE_MSGHDR,
	VEP_RX_STATE_REPLY,
	VEP_RX_STATE_CALL
} vep_rx_state_t;

typedef enum vep_tx_state_e {
	VEP_TX_STATE_IDLE,
	VEP_TX_STATE_TX,
	VEP_TX_STATE_TXERR,
	VEP_TX_STATE_EOR
} vep_tx_state_t;


typedef enum vep_type_e {
	VEP_TYPE_LISTENER,
	VEP_TYPE_CONNECTION
} vep_type_t;

typedef TAILQ_HEAD(txo_list_s, vep_tx_obj_s) txo_list_t;
typedef TAILQ_ENTRY(vep_tx_obj_s) txo_entry_t;

typedef struct vep_tx_obj_s vep_tx_obj_t;
typedef struct vc_ioep_s vc_ioep_t;
typedef struct vep_clnt_call_obj_s vep_clnt_call_obj_t;
typedef struct vep_svc_call_obj_s vep_svc_call_obj_t;

struct vep_tx_obj_s {
	vep_tx_type_t	to_type;
	txo_entry_t	to_listent;
	vep_msgtype_t	to_msgtype;
	int		to_flags;
	union {
		struct {
			char		*buf;
			int		len;
		}	to_buffer;
		struct {
			void		*obj;
			axdrproc_t	xdrp;
		}	to_xdr;
	}		to_data;
	int		to_size;	/* in bytes */
	void		*to_opaque;
	void 		(*to_done)(void *arg, int err);
};

#define TO_FLG_HI_PRIO		0x00000001
#define TO_FLG_SINGLE_BUF	0x00000002

struct vep_clnt_call_obj_s {
	ar_clnt_call_obj_t	vcco_cco;
	vep_tx_obj_t		vcco_call_obj;
};

struct vep_svc_call_obj_s {
	ar_svc_call_obj_t	vsco_sco;
	vep_tx_obj_t		vsco_reply_obj;
};

struct vc_ioep_s {
	axdr_state_t		vep_xdrs;
	uint32_t		vep_flags;
	vep_type_t		vep_type;
	arpc_addr_t		vep_raddr;	/* remote addr */
	ar_vcd_t 		vep_vcd;	/* connection driver */
	void 			*vep_stream;
	vep_as_t		vep_async_rx;
	vep_as_t		vep_async_tx;
	struct timespec 	vep_svc_last_rx;
	struct timespec		vep_estb_limit;
	struct timespec		vep_idle_period;
	ar_ioep_t		vep_ioep;

	/* rx state: */
	vep_rx_state_t		vep_rx_state;
	arpc_msg_t		vep_rx_msg;

	/* tx state: */
	vep_tx_state_t		vep_tx_state;
	txo_list_t		vep_tx_list;
	vep_tx_obj_t		*vep_tx_current;

	uint32_t		vep_flowctl_lo_bytes;
	uint32_t		vep_flowctl_hi_bytes;
	uint32_t		vep_flowctl_cur_bytes;
	uint32_t		vep_flowctl_max_bytes;
	uint32_t		vep_tx_hi_prio;
	uint32_t		vep_tx_hi_prio_guaranteed;
	int			vep_iref_val;
	int			vep_max_connections;
	int			vep_sendsz;
	int			vep_recvsz;

	ar_svc_acceptcb_t	vep_accept_cb;
	void 			*vep_accept_arg;

	ar_conn_cb_t		vep_conn_cb;
	void			*vep_conn_arg;
	int			vep_sys_error;
};

#define VEP_FLG_FROM_LISTEN	0x00000001
#define VEP_FLG_NONBLOCK	0x00000002
#define VEP_FLG_GLOBAL_ERROR	0x00000004
#define VEP_FLG_XDR_ERROR	0x00000008
#define VEP_FLG_FLOWCTL		0x00000010
#define VEP_FLG_CONNECTED	0x00000020
#define VEP_FLG_IDLE_ENFORCE	0x00000040
#define VEP_FLG_DISCONNECTED	0x00000080
#define VEP_FLG_CLEANSHUTDOWN	0x00000100

static void vc_setup(ar_ioep_t ep, struct pollfd *pfd, int *timeoutp);
static void vc_dispatch(ar_ioep_t ep, struct pollfd *pfd);
static void vc_destroy(ar_ioep_t ep);
static int vc_sendmsg(ar_ioep_t ep, arpc_msg_t *, ar_svc_call_obj_t sco);
static int vc_add_client(ar_ioep_t ep, const arpcprog_t, const arpcvers_t,
			 ar_clnt_attr_t *, arpc_err_t *errp,
			 ar_client_t **);
#ifdef HAVE_LIBEVENT
static int vc_event_setup(ar_ioep_t ep, struct event_base *evbase);
#endif

static ep_driver_t vc_ep_driver = {
	vc_setup,
	vc_dispatch,
	vc_destroy,
	vc_sendmsg,
	vc_add_client,
#ifdef HAVE_LIBEVENT
	vc_event_setup
#endif
};

static int vcd_dflt_read(void *vc, struct iovec *vector, int count,
			 size_t *lenp);
static int vcd_dflt_write(void *vc, const struct iovec *vector, int count,
			  size_t *lenp);
static int vcd_dflt_close(void *vc);
static int vcd_dflt_shutdown(void *vc);
static int vcd_dflt_control(void *vc, u_int request, void *info);
static int vcd_dflt_poll_setup(void *vc, struct pollfd *pfd, int *timeoutp);
static int vcd_dflt_poll_dispatch(void *vc, struct pollfd *pfd);
static int vcd_dflt_getfd(void *vc, int *fdp);
static int vcd_dflt_fromfd(ar_svc_attr_t *svc_attr, int fd, void **vc);
static int vcd_dflt_conn(void *vc, const arpc_addr_t *, 
			 arpc_createerr_t *errp);
static int vcd_dflt_accept(void *vc, void **vcpp);
static int vcd_dflt_getladdr(void *vc, arpc_addr_t *);
static int vcd_dflt_getfamily(void *vc, sa_family_t *famp);
static int vcd_dflt_islistener(void *vc, bool_t *listenp);
static int vcd_dflt_listen(void *vc, const arpc_addr_t *);
static int vcd_dflt_init(ar_clnt_attr_t *attr, ar_svc_attr_t *svc_attr, 
			 void **vcpp);
static int vcd_dflt_destroy(void *vcp);

static struct ar_vcd_s vcd_default = {
	vcd_dflt_read,
	vcd_dflt_write,
	vcd_dflt_close,
	vcd_dflt_shutdown,
	vcd_dflt_control,
	vcd_dflt_poll_setup,
	vcd_dflt_poll_dispatch,
	vcd_dflt_getfd,
	vcd_dflt_fromfd,
	vcd_dflt_conn,
	vcd_dflt_accept,
	vcd_dflt_getladdr,
	vcd_dflt_getfamily,
	vcd_dflt_islistener,
	vcd_dflt_listen,
	vcd_dflt_init,
	vcd_dflt_destroy,
	0
};

typedef enum vcd_dflt_state_e {
	VCDD_STATE_CLOSED = 1,
	VCDD_STATE_CONNECTING,
	VCDD_STATE_ESTABLISHED,
	VCDD_STATE_SHUTDOWN,
	VCDD_STATE_LISTEN,
	VCDD_STATE_ERROR
} vcd_dflt_state_t;

typedef struct vcd_dflt_ctx_s {
	vcd_dflt_state_t	vdc_state;
	int			vdc_fd;
	char			vdc_buf[8];
	int			vdc_bufcnt;
	int			vdc_err;
	int			vdc_events;
} vcd_dflt_ctx_t;


static void vc_dispatch_connected(ar_ioep_t ep, ar_stat_t);
static void vc_dispatch_disconnect(ar_ioep_t ep, ar_stat_t);

static int clnt_vc_call(ar_client_t *, arpcproc_t, axdrproc_t, void *, 
			bool_t inplace, axdrproc_t, void *, int, 
			ar_clnt_async_cb_t, void *, struct timespec *, 
			ar_clnt_call_obj_t *);
static void clnt_vc_destroy(ar_client_t *);
static bool_t clnt_vc_control(ar_client_t *, u_int, void *);
static int clnt_vc_handoff(ar_client_t *, ar_client_t *, cco_list_t *,
			   struct ar_xid_state_s *xstate,
			   arpc_createerr_t *errp);
static int clnt_vc_cancel(ar_client_t *, ar_clnt_call_obj_t cco);
static void clnt_vc_reauth(ar_client_t *, ar_clnt_call_obj_t cco);
static void clnt_vc_call_dropref(ar_client_t *, ar_clnt_call_obj_t cco);

static struct clnt_ops vc_clnt_ops = {
	clnt_vc_call, 
	clnt_vc_destroy,
	clnt_vc_control,
	clnt_vc_handoff,
	clnt_vc_cancel,
	clnt_vc_reauth,
	clnt_vc_call_dropref
};

static int xp_vc_sco_reply(ar_svc_xprt_t *xp, ar_svc_call_obj_t sco);
static int xp_vc_sco_alloc(ar_svc_xprt_t *xp, ar_svc_call_obj_t *scop);
static void xp_vc_sco_destroy(ar_svc_xprt_t *xp, ar_svc_call_obj_t sco);
static void xp_vc_destroy(ar_svc_xprt_t *xp);
static bool_t xp_vc_control(ar_svc_xprt_t *xp, const u_int cmd, void *info);

static struct xp_ops vc_xp_ops = {
	xp_vc_sco_reply,
	xp_vc_sco_alloc,
	xp_vc_sco_destroy,
	xp_vc_destroy,
	xp_vc_control
};

static void vc_cco_destroy(ar_clnt_call_obj_t cco);
static void vc_ioep_destroy(ar_ioep_t ioep);
static void vc_clnt_bumpref(ar_client_t *cl);
static void vc_clnt_dropref(ar_client_t *cl);
static void vc_cco_bumpref(ar_clnt_call_obj_t cco);
static void vc_cco_dropref(ar_clnt_call_obj_t cco);
static void vc_sco_bumpref(ar_svc_call_obj_t sco);
static void vc_sco_dropref(ar_svc_call_obj_t sco);
static void vc_xp_bumpref(ar_svc_xprt_t *xp);
static void vc_xp_dropref(ar_svc_xprt_t *xp);
static void vc_ioep_bumpref(ar_ioep_t ioep);
static void vc_ioep_dropref(ar_ioep_t ioep);
static void vc_update_flowctl(vc_ioep_t *vep);
static void vc_update_listener_flowctl(ar_ioctx_t ioctx);
static void io_vcd_ep_destroy(ar_ioep_t ioep);
static void vep_reset_async(vep_as_t *as);

static int
vc_syscreat_err(arpc_createerr_t *errp, int err)
{
	if (errp) {
		ar_errno2err(&errp->cf_error, err);
		errp->cf_stat = errp->cf_error.re_status;
	}
	return err;
}

static void
vc_clnt_destroy(ar_client_t *cl)
{
	ar_clnt_call_obj_t	cco;
	ar_clnt_call_obj_t	cconext;
	ar_ioep_t		ioep;
	vc_ioep_t		*vep;
	arpc_err_t		result;

	assert(cl != NULL);

	cl->cl_flags |= CLNT_FLG_DESTROY;
	cl->cl_refcnt++;	/* for safety */

	memset(&result, 0, sizeof(result));
	if (cl->cl_queued_err < 0) {
		/* set a generic error */
		cl->cl_queued_err = EIO;
		result.re_status = ARPC_INTR;
	} else {
		ar_errno2err(&result, cl->cl_queued_err);
	}

	ioep = cl->cl_ioep;
	if (ioep) {
		vep = (vc_ioep_t *)ioep->iep_drv_arg;
		assert(vep != NULL);

		vc_ioep_bumpref(ioep);

		TAILQ_REMOVE(&ioep->iep_client_list, cl, cl_listent);
		cl->cl_refcnt -= vep->vep_iref_val;
		cl->cl_ioep = NULL;
		cl->cl_private = NULL;

		/* pick out everything we want to destroy and put it in
		 * the front of the list.
		 */
		for (cco = TAILQ_FIRST(&ioep->iep_clnt_calls);
		     cco; cco = cconext) {
			cconext = TAILQ_NEXT(cco, cco_listent);
			if (cco->cco_client == cl) {
				TAILQ_REMOVE(&ioep->iep_clnt_calls, cco, 
					     cco_listent);
				TAILQ_INSERT_HEAD(&ioep->iep_clnt_calls, cco,
						  cco_listent);
			}
		}

		while ((cco = TAILQ_FIRST(&ioep->iep_clnt_calls)) != NULL &&
		       cco->cco_client == cl) {
			cco->cco_rpc_err = result;
			vc_cco_bumpref(cco);
			if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
				/* steal back usr reference, after notify */
				cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
				(*cco->cco_cb)(cco, cco->cco_cb_arg, 
					       &result, NULL);
				/* cco destroy needs to know ioep */
				cl->cl_ioep = ioep;
				vc_cco_destroy(cco);
				cl->cl_ioep = NULL;
				/* actually drop usr ref */
				vc_cco_dropref(cco);	
			} else {
				/* can this happen? */
				/* cco destroy needs to know ioep */
				cl->cl_ioep = ioep;
				vc_cco_destroy(cco);
				cl->cl_ioep = NULL;
			}
			vc_cco_dropref(cco);	
		}

		/* release reference to ioep */
		if (TAILQ_FIRST(&ioep->iep_client_list) == NULL) {
			if (((cl->cl_flags & CLNT_FLG_KILL_SVC) != 0 ||
			     !ioep->iep_svc_ctx)) {
				/* we're the last client and there is no server
				 * context.  Destroy the connection.
				 */
				vc_ioep_destroy(ioep);
			} else {
				/* must idle out if it's going to remain
				 * as just a server connection.
				 */
				vep->vep_flags |= VEP_FLG_IDLE_ENFORCE;
			}
		}

		/* try to reclaim user reference if we need it */
		if ((cl->cl_flags & CLNT_FLG_USRREF_DEC) == 0) {
			if ((vep->vep_flags & VEP_FLG_CONNECTED) != 0 &&
			    (cl->cl_flags & CLNT_FLG_DISCON_CALLED) == 0 && 
			    cl->cl_discon_cb != NULL) {
				cl->cl_flags |= CLNT_FLG_DISCON_CALLED;
				(*cl->cl_discon_cb)(cl, cl->cl_discon_cb_arg,
						    &result);
			}
			if ((vep->vep_flags & VEP_FLG_CONNECTED) == 0 &&
			    cl->cl_conn_cb != NULL) {
			    arpc_createerr_t cerr;
			    memset(&cerr, 0, sizeof(cerr));

			    cerr.cf_stat = result.re_status;
			    cerr.cf_error = result;
			    (*cl->cl_conn_cb)(cl, cl->cl_conn_cb_arg, &cerr);
			}
		}

		vc_ioep_dropref(ioep);
	}

	cl->cl_refcnt--;
	if (cl->cl_refcnt <= 0) {
		free(cl);
	}
}


static void
vc_cco_destroy(ar_clnt_call_obj_t cco)
{
	vep_tx_obj_t	*txo;
	ar_client_t	*cl;
	ar_ioep_t	ioep;
	vc_ioep_t	*vep;

	assert(cco != NULL);
	txo = (vep_tx_obj_t *)cco->cco_lower;
	cl = cco->cco_client;
	assert(cl != NULL && txo != NULL);
	if (cco->cco_state != CCO_STATE_DEAD) {
		ioep = cl->cl_ioep;
		assert(ioep != NULL);
		vep = (vc_ioep_t *)ioep->iep_drv_arg;
		assert(vep != NULL);
	} else {
		vep = NULL;
		ioep = NULL;
	}

	cco->cco_flags |= CCO_FLG_DESTROY;
	if (cco->cco_state == CCO_STATE_PENDING) {
		if (vep->vep_tx_current == txo) {
			switch (vep->vep_tx_state) {
			case VEP_TX_STATE_TX:
			case VEP_TX_STATE_EOR:
				vep->vep_tx_current = NULL;
				vep->vep_tx_state = VEP_TX_STATE_TXERR;
				break;
			default:
				assert(FALSE);
			}
		} else {
			TAILQ_REMOVE(&vep->vep_tx_list, txo, to_listent);
			vc_update_flowctl(vep);
		}
	}
		
	switch (cco->cco_state) {
	case CCO_STATE_QUEUED:
	case CCO_STATE_RESULTS:
	case CCO_STATE_DONE:
	case CCO_STATE_PENDING:
	case CCO_STATE_RUNNING:
		TAILQ_REMOVE(&ioep->iep_clnt_calls, cco, cco_listent);
		TAILQ_NEXT(cco, cco_listent) = NULL;
		ar_clnt_cco_cleanup(ioep->iep_auth, cco);

		if (ioep->iep_clnt_reply == cco) {
			ioep->iep_clnt_reply = NULL;
			axdr_free((axdrproc_t)axdr_msg, &vep->vep_rx_msg);
			memset(&vep->vep_rx_msg, 0, sizeof(vep->vep_rx_msg));
			/* reset async machine (more important on error path), 
			 * and go back to skip record. 
			 */
			vep_reset_async(&vep->vep_async_rx);
			vep->vep_rx_state = VEP_RX_STATE_SKIPRECORD;
		}
		break;
	case CCO_STATE_DEAD:
		/* already off all the lists */
		break;
	default:
		assert(FALSE);
	}

	cco->cco_state = CCO_STATE_DEAD;

	if (cco->cco_refcnt > 0) {
		/* can only clean up so much stuff since we still have
		 * references.
		 */
		return;
	}

	/* release cco's reference to client */
	vc_clnt_dropref(cl);

	if ((txo->to_flags & TO_FLG_SINGLE_BUF) != 0) {
		free(cco);
	} else {
		free(cco);
		free(txo);
	}
}

static void
vc_sco_destroy(ar_svc_call_obj_t sco)
{
	vep_tx_obj_t	*txo;
	ar_svc_xprt_t		*xp;
	ar_ioep_t	ioep;
	vc_ioep_t	*vep;

	assert(sco != NULL);
	txo = (vep_tx_obj_t *)sco->sco_lower;
	xp = sco->sco_xp;
	assert(xp != NULL && txo != NULL);
	if (sco->sco_state != SCO_STATE_DEAD) {
		ioep = xp->xp_ioep;
		assert(ioep != NULL);
		vep = (vc_ioep_t *)ioep->iep_drv_arg;
		assert(vep != NULL);
	} else {
		vep = NULL;
		ioep = NULL;
	}

	if (sco->sco_state == SCO_STATE_GET_ARGS) {
		assert(ioep->iep_svc_call == sco);
		/* reset rx machine */
		axdr_free((axdrproc_t)axdr_msg, &vep->vep_rx_msg);
		memset(&vep->vep_rx_msg, 0, sizeof(vep->vep_rx_msg));
		/* reset async machine (more important on error path), 
		 * and go back to skip record. 
		 */
		vep_reset_async(&vep->vep_async_rx);
		vep->vep_rx_state = VEP_RX_STATE_SKIPRECORD;
		ioep->iep_svc_call = NULL;
		sco->sco_state = SCO_STATE_INIT;
	}

	if ((sco->sco_flags & SCO_FLG_DESTROY) == 0 &&
	    sco->sco_state == SCO_STATE_SEND_REPLY) {
		if (vep->vep_tx_current == txo) {
			switch (vep->vep_tx_state) {
			case VEP_TX_STATE_TX:
			case VEP_TX_STATE_EOR:
				vep->vep_tx_current = NULL;
				vep->vep_tx_state = VEP_TX_STATE_TXERR;
				break;
			default:
				assert(FALSE);
			}
		} else {
			TAILQ_REMOVE(&vep->vep_tx_list, txo, to_listent);
			vc_update_flowctl(vep);
		}
	}

	ar_svc_sco_unlink(sco);
	sco->sco_flags |= SCO_FLG_DESTROY;

	if (sco->sco_refcnt > 0) {
		/* can only clean up so much stuff since we still have
		 * references.
		 */
		return;
	}

	/* do this after the references are gone, because the server
	 * is given a pointer to the results buffer, and we don't want
	 * to free it before they're done with it.
	 */
	ar_svc_sco_cleanup(sco);

	/* release sco's reference to ar_svc_xprt_t */
	vc_xp_dropref(xp);

	free(sco);
}


static void
vc_xp_destroy(ar_svc_xprt_t *xp)
{
	ar_svc_call_obj_t	sco;
	ar_ioep_t	ioep;
	vc_ioep_t	*vep;

	assert(xp != NULL);

	xp->xp_flags |= XP_FLG_DESTROY;
	xp->xp_refcnt++;	/* for safety */

	if (xp->xp_queued_err < 0) {
		/* set a generic error */
		xp->xp_queued_err = EIO;
	}

	ioep = xp->xp_ioep;
	if (ioep) {
		vep = (vc_ioep_t *)ioep->iep_drv_arg;
		assert(vep != NULL);

		assert(ioep->iep_svc_ctx == xp);

		vc_ioep_bumpref(ioep);

		while ((sco = TAILQ_FIRST(&ioep->iep_svc_async_calls)) 
		       != NULL) {
			/* if the usr ref has not be released, we can't
			 * do anything more until the call is done or canceled
			 */
			vc_sco_destroy(sco);
		}

		while ((sco = TAILQ_FIRST(&ioep->iep_svc_replies)) != NULL) {
			vc_sco_destroy(sco);
		}

		ioep->iep_svc_ctx = NULL;
		xp->xp_ioep = NULL;

		if (TAILQ_FIRST(&ioep->iep_client_list) == NULL) {
			/* Server context gone and no clients.  Remove 
			 * connection.  (But only if we're the last
			 * reference.) This prevents recursion when
			 * we're called from vc_ioep_destroy.
			 */
			ioep->iep_flags |= IEP_FLG_DESTROY;
		}

		vc_ioep_dropref(ioep);
	}

	if ((xp->xp_flags & XP_FLG_USRREF_DEC) == 0 && 
	    xp->xp_error_cb != NULL) {
		(*xp->xp_error_cb)(xp->xp_ioctx, xp, xp->xp_error_arg, 
				   xp->xp_queued_err);
	}

	xp->xp_refcnt--;
	if (xp->xp_refcnt <= 0) {
		free(xp);
	}
}


static void
vc_ioep_destroy(ar_ioep_t ioep)
{
	ar_ioctx_t	ioctx;
	vep_tx_obj_t	*txo;
	vc_ioep_t	*vep;
	ar_svc_xprt_t		*xp;
	ar_client_t		*cl;

	assert(ioep != NULL);

	RPCTRACE(ioep->iep_ioctx, 3, "vc_ioep_destroy() ioep %p\n", ioep);
	
	ioep->iep_flags |= IEP_FLG_DESTROY;
	vep = (vc_ioep_t *)ioep->iep_drv_arg;
	assert(vep != NULL);

	ioep->iep_refcnt++;	/* prevent it from going away */

	/* all ioep references come through the cnt or svc structures.
	 * If we kill those everything else should disappear.
	 */
	while ((cl = TAILQ_FIRST(&ioep->iep_client_list)) != NULL) {
		if (cl->cl_queued_err < 0 && vep->vep_sys_error > 0) {
			cl->cl_queued_err = vep->vep_sys_error;
		}
		vc_clnt_destroy(cl);
	}

	xp = ioep->iep_svc_ctx;
	if (xp) {
		if (xp->xp_queued_err < 0 && vep->vep_sys_error > 0) {
			xp->xp_queued_err = vep->vep_sys_error;
		}
		vc_xp_destroy(xp);
	}

	while ((txo = TAILQ_FIRST(&vep->vep_tx_list)) != NULL) {
		TAILQ_REMOVE(&vep->vep_tx_list, txo, to_listent);
		assert(txo->to_msgtype == VEP_MSGTYPE_SYNC_REPLY);
		assert(txo->to_type == VEP_TX_TYPE_BUF);
		if (txo->to_data.to_buffer.buf) {
			free(txo->to_data.to_buffer.buf);
		}
		txo->to_data.to_buffer.buf = NULL;
		free(txo);
	}

	txo = vep->vep_tx_current;
	if (txo) {
		vep->vep_tx_current = NULL;
		assert(txo->to_msgtype == VEP_MSGTYPE_SYNC_REPLY);
		assert(txo->to_type == VEP_TX_TYPE_BUF);
		if (txo->to_data.to_buffer.buf) {
			free(txo->to_data.to_buffer.buf);
		}
		txo->to_data.to_buffer.buf = NULL;
		free(txo);
	}

#ifdef HAVE_LIBEVENT
	/* delete and free up monitored event */
	if (ioep->iep_event) {
		event_del(ioep->iep_event);
		event_free(ioep->iep_event);
		ioep->iep_event = NULL;
	}
#endif
	
	ioctx = ioep->iep_ioctx;
	if (ioctx) {
		TAILQ_REMOVE(&ioctx->icx_ep_list, ioep, iep_listent);
		ioep->iep_ioctx = NULL;
		/* may allow a new connection now */
		vc_update_listener_flowctl(ioctx);
	}

	assert(vep->vep_tx_current == NULL);
	assert(ioep->iep_clnt_reply == NULL);
	assert(ioep->iep_svc_call == NULL);
	assert(TAILQ_FIRST(&vep->vep_tx_list) == NULL);

	/* release our reference */
	ioep->iep_refcnt--;

	if (ioep->iep_refcnt > 0) {
		/* not yet able to really clean up the structure */
		return;
	}

	io_vcd_ep_destroy(ioep);
}


static void
vc_clnt_bumpref(ar_client_t *cl)
{
	assert(cl != NULL);
	cl->cl_refcnt++;
}

static void
vc_clnt_dropref(ar_client_t *cl)
{
	assert(cl != NULL);
	cl->cl_refcnt--;
	if (cl->cl_refcnt <= 0  &&
	    (cl->cl_flags & CLNT_FLG_DESTROY) != 0) {
		vc_clnt_destroy(cl);
	}
}

static void
vc_cco_bumpref(ar_clnt_call_obj_t cco)
{
	assert(cco != NULL);
	cco->cco_refcnt++;
}

static void
vc_cco_dropref(ar_clnt_call_obj_t cco)
{
	assert(cco != NULL);
	cco->cco_refcnt--;
	if (cco->cco_refcnt <= 0 &&
	    (cco->cco_flags & CCO_FLG_DESTROY) != 0) {
		vc_cco_destroy(cco);
	}
}

static void 
clnt_vc_call_dropref(ar_client_t *cl, ar_clnt_call_obj_t cco)
{
	vc_cco_dropref(cco);
}

static void
vc_sco_bumpref(ar_svc_call_obj_t sco)
{
	assert(sco != NULL);
	sco->sco_refcnt++;
}

static void
vc_sco_dropref(ar_svc_call_obj_t sco)
{
	assert(sco != NULL);
	sco->sco_refcnt--;
	if (sco->sco_refcnt <= 0 && 
	    (sco->sco_flags & SCO_FLG_DESTROY) != 0) {
		vc_sco_destroy(sco);
	}
}

static void
vc_xp_bumpref(ar_svc_xprt_t *xp)
{
	assert(xp != NULL);
	xp->xp_refcnt++;
}

static void
vc_xp_dropref(ar_svc_xprt_t *xp)
{
	assert(xp != NULL);
	xp->xp_refcnt--;
	if (xp->xp_refcnt <= 0 && 
	    (xp->xp_flags & XP_FLG_DESTROY) != 0) {
		vc_xp_destroy(xp);
	}
}

static void
vc_ioep_bumpref(ar_ioep_t ioep)
{
	assert(ioep != NULL);
	ioep->iep_refcnt++;
}

static void
vc_ioep_dropref(ar_ioep_t ioep)
{
	assert(ioep != NULL);
	ioep->iep_refcnt--;
	if (ioep->iep_refcnt <= 0 && 
	    (ioep->iep_flags & IEP_FLG_DESTROY) != 0) {
		vc_ioep_destroy(ioep);
	}
}

static void
vc_update_listener_flowctl(ar_ioctx_t ioctx)
{
	ar_ioep_t	ioep;
	vc_ioep_t	*vep;
	int		count;

	count = 0;
	TAILQ_FOREACH(ioep, &ioctx->icx_ep_list, iep_listent) {
		if (ioep->iep_drv != &vc_ep_driver) {
			continue;
		}
		vep = (vc_ioep_t *)ioep->iep_drv_arg;
		if ((vep->vep_flags & VEP_FLG_FROM_LISTEN) == 0 ||
		    vep->vep_type != VEP_TYPE_CONNECTION) {
			continue;
		}
		count++;
	}

	TAILQ_FOREACH(ioep, &ioctx->icx_ep_list, iep_listent) {
		if (ioep->iep_drv != &vc_ep_driver) {
			continue;
		}
		vep = (vc_ioep_t *)ioep->iep_drv_arg;
		if (vep->vep_type != VEP_TYPE_LISTENER) {
			continue;
		}
		if (count >= vep->vep_max_connections) {
			vep->vep_flags |= VEP_FLG_FLOWCTL;
		} else {
			vep->vep_flags &= ~VEP_FLG_FLOWCTL;
		}
	}

	return;
}


static void
vc_update_flowctl(vc_ioep_t *vep)
{
	vep_tx_obj_t	*txo;
	ar_ioep_t	ioep;
	ar_ioep_t	ep2;
	ar_ioctx_t	ioctx;
	vc_ioep_t	*vep2;
	int count;
	int hiprio;
	int size;

	ioep = vep->vep_ioep;
	ioctx = ioep->iep_ioctx;
	
	if (vep->vep_type == VEP_TYPE_LISTENER) {
		count = 0;
		TAILQ_FOREACH(ep2, &ioctx->icx_ep_list, iep_listent) {
			if (ep2 == ioep) {
				continue;
			}
			if (ioep->iep_drv != &vc_ep_driver) {
				continue;
			}
			vep2 = (vc_ioep_t *)ep2->iep_drv_arg;
			if ((vep2->vep_flags & VEP_FLG_FROM_LISTEN) == 0 ||
			    vep2->vep_type != VEP_TYPE_CONNECTION) {
				continue;
			}
			count++;
		}
		if (count >= vep->vep_max_connections) {
			vep->vep_flags |= VEP_FLG_FLOWCTL;
		} else {
			vep->vep_flags &= ~VEP_FLG_FLOWCTL;
		}
		return;
	}

	/* update connection flow control */
	size = 0;
	hiprio = 0;
	TAILQ_FOREACH(txo, &vep->vep_tx_list, to_listent) {
		size += sizeof(*txo) + txo->to_size;
		if (txo->to_flags & TO_FLG_HI_PRIO) {
			hiprio++;
		}
	}

	vep->vep_flowctl_cur_bytes = size;
	vep->vep_tx_hi_prio = hiprio;

	if (size < vep->vep_flowctl_lo_bytes) {
		vep->vep_flags &= ~VEP_FLG_FLOWCTL;
		return;
	}

	if (TAILQ_FIRST(&ioep->iep_clnt_calls) != NULL) {
		/* can't flow control rx because we have
		 * outstanding calls....
		 */
		vep->vep_flags &= ~VEP_FLG_FLOWCTL;
		return;
	}

	if (size >= vep->vep_flowctl_hi_bytes) {
		vep->vep_flags |= VEP_FLG_FLOWCTL;
	}
}

static void
vep_reset_async(vep_as_t *as)
{
	astk_cleanup(&as->as_stack);
	astk_init(&as->as_stack);
#if 0
	/* FIXME: */
	astk_set_buf(&as->as_stack, as->as_buf, sizeof(as->as_buf), 
			  FALSE);
#endif
}


static void
vep_init_async(vep_as_t *as)
{
	astk_init(&as->as_stack);
#if 0
	/* FIXME: */
	astk_set_buf(&as->as_stack, as->as_buf, sizeof(as->as_buf), 
			  FALSE);
#endif
}

static void
vc_queue_syserror(vc_ioep_t *vep, int err)
{
	if (vep->vep_sys_error <= 0) {
		vep->vep_sys_error = err;
	}
}

static void
vc_syserror(vc_ioep_t *vep, int err)
{
	ar_ioep_t	ioep;

	assert(vep != NULL);

	if (vep->vep_sys_error <= 0) {
		vep->vep_sys_error = err;
	}
	ioep = vep->vep_ioep;

	vc_ioep_destroy(ioep);
}


static int
vc_epd_read_check(ar_ioctx_t ioctx, vc_ioep_t *vep, ar_ioep_t ioep)
{
	axdr_ret_t rval;
	ar_clnt_call_obj_t cco;
	ar_svc_call_obj_t sco;
	arpc_err_t result;
	bool_t empty;
	int err;

	switch (vep->vep_rx_state) {
	case VEP_RX_STATE_SKIPRECORD:
		rval = axdrrec_skiprecord(&vep->vep_xdrs);
		if (rval != AXDR_DONE) {
			/* error or waiting */
			if (rval == AXDR_ERROR) {
				return EPARSE;
			} else {
				return EAGAIN;
			}
		}
		/* zero msg structure before we start. That gurantee's 
		 * we won't double free, and the body callback ptr is 
		 * null, so we don't jump into the weeds.
		 */
		memset(&vep->vep_rx_msg, 0, sizeof(vep->vep_rx_msg));
		vep_reset_async(&vep->vep_async_rx);

		/* make sure the clnt and svc layers have initial state
		 * as well.
		 */
		sco = ar_svc_new_rx_msg(ioep);
		if (sco) {
			vc_sco_destroy(sco);
		}
		cco = ar_clnt_new_rx_msg(ioep);
		/* clear out partial state if we have it */
		if (cco) {
			vc_cco_destroy(cco);
		}

		rval = axdrrec_empty(&vep->vep_xdrs, &empty);
		if (rval == AXDR_DONE && empty) {
			if (vep->vep_flags & VEP_FLG_DISCONNECTED) {
				/* we're disconnected, have no rx data buffered
				 * and are between messages.  This is a 
				 * clean shutdown.  Notify accordingly.
				 */
				vc_dispatch_disconnect(ioep, ARPC_SUCCESS);
				/* this causes anything that's outstanding
				 * to fail still.
				 */
				vc_syserror(vep, ENOTCONN);
				return 0;
			}
			/* note that a clean shutdown is allowed 
			 * at this point.  This is cleared by the read
			 * hook if a zero read is not received on the
			 * next call to the read hook.
			 */
			vep->vep_flags |= VEP_FLG_CLEANSHUTDOWN;
		}

		vep->vep_rx_state = VEP_RX_STATE_MSGHDR;
		/* fall through */
	case VEP_RX_STATE_MSGHDR:
		rval = axdr_msg(&vep->vep_xdrs, &vep->vep_rx_msg);
		if (rval != AXDR_DONE) {
			if (rval != AXDR_WAITING) {
				/* free call obj */
				if (ioep->iep_flags & IEP_FLG_DESTROY) {
					/* somebody has already cleand up for
					 * us.
					 */
					return 0;
				}

				axdr_free((axdrproc_t)axdr_msg, &vep->vep_rx_msg);
				memset(&vep->vep_rx_msg, 0, 
				       sizeof(vep->vep_rx_msg));

				/* flag error */
				vep->vep_flags |= VEP_FLG_XDR_ERROR;

				/* reset async machine */
				vep_reset_async(&vep->vep_async_rx);
				vep->vep_rx_state = VEP_RX_STATE_SKIPRECORD;
				return 0;
			} else {
				/* waiting for more data */
				return EAGAIN;
			}
		}

		switch (vep->vep_rx_msg.arm_direction) {
		case AR_REPLY:
			vep->vep_rx_state = VEP_RX_STATE_REPLY;
			return 0;
		case AR_CALL:
			vep->vep_rx_state = VEP_RX_STATE_CALL;
			return 0;
		default:
			/* free call obj */
			axdr_free((axdrproc_t)axdr_msg, &vep->vep_rx_msg);
			memset(&vep->vep_rx_msg, 0, sizeof
			       vep->vep_rx_msg);
			/* flag error */
			vep->vep_flags |= VEP_FLG_XDR_ERROR;

			/* reset async machine */
			vep_reset_async(&vep->vep_async_rx);
			vep->vep_rx_state = VEP_RX_STATE_SKIPRECORD;
			return 0;
		}
		/* not reached */
		return EINVAL;
	case VEP_RX_STATE_REPLY:
		rval = ar_clnt_handle_reply(&vep->vep_xdrs, ioep, 
					 &vep->vep_rx_msg, &cco);
		if (rval == AXDR_WAITING) {
			return EAGAIN;
		}
		if (cco) {
			vc_cco_bumpref(cco);
			if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
				cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
				vc_cco_dropref(cco);
				result = cco->cco_rpc_err;
				(*cco->cco_cb)(cco, cco->cco_cb_arg, 
					       &result, cco->cco_resp);
				/* it is safe to continue processing here
				 * since no user code can call a read
				 * check except for the top level dispatch.
				 * The user should never call that from
				 * a completion callback.
				 */
			}
			vc_cco_destroy(cco);
			vc_cco_dropref(cco);
		}

		/* always free the header obj (either error or done) */
		axdr_free((axdrproc_t)axdr_msg, &vep->vep_rx_msg);
		memset(&vep->vep_rx_msg, 0, sizeof(vep->vep_rx_msg));

		/* reset async machine (more important on error path), 
		 * and go back to skip record. 
		 */
		vep_reset_async(&vep->vep_async_rx);
		vep->vep_rx_state = VEP_RX_STATE_SKIPRECORD;

		if (rval == AXDR_ERROR) {
			/* flag error */
			vep->vep_flags |= VEP_FLG_XDR_ERROR;
		}
		return 0;
	case VEP_RX_STATE_CALL:
		rval = ar_svc_handle_call(&vep->vep_xdrs, ioep, 
					  &vep->vep_rx_msg, &sco);
		if (rval == AXDR_WAITING) {
			return EAGAIN;
		}

		if (sco) {
			/* need to queue up for xmit */
			assert(sco->sco_state == SCO_STATE_CALL);
			err = xp_vc_sco_reply(ioep->iep_svc_ctx, sco);
			if (err != 0) {
				vc_sco_destroy(sco);
			}
		}

		/* always free the header obj (either error or done) */
		axdr_free((axdrproc_t)axdr_msg, &vep->vep_rx_msg);
		memset(&vep->vep_rx_msg, 0, sizeof
		       vep->vep_rx_msg);

		/* reset async machine (more important on error path), 
		 * and go back to skip record. 
		 */
		vep_reset_async(&vep->vep_async_rx);
		vep->vep_rx_state = VEP_RX_STATE_SKIPRECORD;

		if (rval == AXDR_ERROR) {
			/* flag error */
			vep->vep_flags |= VEP_FLG_XDR_ERROR;
		}
		return 0;
	default:
		return EINVAL;
	}
}


static int
vc_epd_write_check(ar_ioctx_t ioctx, vc_ioep_t *vep, ar_ioep_t ep)
{
	vep_tx_obj_t *txo;
	void *obj;
	axdrproc_t axdrfn;
	axdr_ret_t rval;

	switch (vep->vep_tx_state) {
	case VEP_TX_STATE_IDLE:
		txo = TAILQ_FIRST(&vep->vep_tx_list);
		if (!txo) {
			/* nothing to do */
			return EAGAIN;
		}
		if (vep->vep_tx_current) {
			/* what?? */
			return EINVAL;
		}

		TAILQ_REMOVE(&vep->vep_tx_list, txo, to_listent);
		vep_reset_async(&vep->vep_async_tx);
		vc_update_flowctl(vep);
		vep->vep_tx_current = txo;
		vep->vep_tx_state = VEP_TX_STATE_TX;
		/* fallthrough */
	case VEP_TX_STATE_TX:
		txo = vep->vep_tx_current;
		if (!txo) {
			return EINVAL;
		}
		switch (txo->to_type) {
		case VEP_TX_TYPE_XDR:
			axdrfn = txo->to_data.to_xdr.xdrp;
			obj = txo->to_data.to_xdr.obj;
			rval = (*axdrfn)(&vep->vep_xdrs, obj);
			break;
		case VEP_TX_TYPE_BUF:
			rval = axdr_opaque(&vep->vep_xdrs,
					   txo->to_data.to_buffer.buf, 
					   txo->to_data.to_buffer.len);
			break;
		default:
			return EINVAL;
		}

		if (rval != AXDR_DONE) {
			if (rval != AXDR_WAITING) {
				if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
					/* low level io error. Just
					 * get out of here.
					 */
					return EAGAIN;
				}

				/* encode error.  Just terminate the frame
				 * and fail the call
				 */
				/* vc_call_sent can now complete
				 * calls, which results in a callback
				 * to user code.  The user code can
				 * create new calls, which attempt to send.
				 * That results in  recursive entry to this
				 * function.  Return to our main loop, so
				 * if the recursive guy pushes us through
				 * the TX err state, etc. everything works
				 * out correctly.
				 */
				(*txo->to_done)(txo->to_opaque, EPARSE);

				/* if the cleanup didn't update our 
				 * state, do that now.
				 */
				if (vep->vep_tx_current == txo) {
					vep->vep_tx_current = NULL;
					vep->vep_tx_state = VEP_TX_STATE_TXERR;
				}
				return 0;
			} else {
				/* waiting */
				return EAGAIN;
			}
		} else {
			vep->vep_tx_state = VEP_TX_STATE_EOR;
		}
		/* fallthrough */
	case VEP_TX_STATE_EOR:
	case VEP_TX_STATE_TXERR:
		txo = vep->vep_tx_current;
		if (vep->vep_tx_state == VEP_TX_STATE_EOR && !txo) {
			return EINVAL;
		}

		/* do the flush so we get any error's associated with the
		 * correct call.
		 */
		rval = axdrrec_endofrecord(&vep->vep_xdrs, TRUE);
		if (rval != AXDR_DONE) {
			if (rval != AXDR_WAITING) {
				return EIO;
			} else {
				return EAGAIN;
			}
		}

		if (vep->vep_tx_state == VEP_TX_STATE_EOR) {
			(*txo->to_done)(txo->to_opaque, 0);
		}

		vep->vep_tx_current = NULL;
		vep_reset_async(&vep->vep_async_tx);
		vep->vep_tx_state = VEP_TX_STATE_IDLE;

		/* try for the next operation */
		return 0;
	default:
		return EINVAL;
	}
}

				
static void
vc_read(ar_ioctx_t ioctx, vc_ioep_t *vep, ar_ioep_t ep)
{
	int err;

	if (!vep || !ioctx || !ep) {
		return;
	}

	vep->vep_xdrs.x_async = &vep->vep_async_rx.as_stack;
	vep->vep_xdrs.x_op = AXDR_DECODE_ASYNC;

	while ((vep->vep_flags & VEP_FLG_FLOWCTL) == 0) {
		err = vc_epd_read_check(ioctx, vep, ep);
		if (err != 0 && err != EAGAIN) {
			vc_syserror(vep, err);
			break;
		}
		if (err == EAGAIN || 
		    (ep->iep_flags & IEP_FLG_DESTROY) != 0) {
			break;
		}
	}
}


static void
vc_write(ar_ioctx_t ioctx, vc_ioep_t *vep, ar_ioep_t ep)
{
	int err;

	if (!vep || !ioctx || !ep) {
		return;
	}

	vep->vep_xdrs.x_async = &vep->vep_async_tx.as_stack;
	vep->vep_xdrs.x_op = AXDR_ENCODE_ASYNC;

	for (;;) {
		err = vc_epd_write_check(ioctx, vep, ep);
		if (err != 0 && err != EAGAIN) {
			vc_syserror(vep, err);
			break;
		}
		if (err == EAGAIN ||
		    (ep->iep_flags & IEP_FLG_DESTROY) != 0) {
			break;
		}
	}
}

static void
vc_setup(ar_ioep_t ep, struct pollfd *pfd, int *timeoutp)
{
	vc_ioep_t *vep;
	ar_clnt_call_obj_t cco;
	struct timespec cur;
	struct timespec diff;
	int timeout;
	int period;
	int err;

	/* setup what we want first, then let the vcd layer filter it
	 */
	if (pfd) {
		pfd->fd = -1;
		pfd->events = 0;
	}

	if (timeoutp) {
		*timeoutp = 0;
	}
	
	if (!timeoutp || !pfd || !ep || ep->iep_type != IOEP_TYPE_VC) {
		return;
	}

	vep = ep->iep_drv_arg;
	if (!vep) {
		return;
	}

	if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
		return;
	}

	*timeoutp = -1;

	pfd->fd = -1;

	timeout = -1;

	switch (vep->vep_type) {
	case VEP_TYPE_CONNECTION:
		if ((vep->vep_flags & VEP_FLG_FLOWCTL) == 0) {
			pfd->events |= POLLIN;
		}

		if (TAILQ_FIRST(&vep->vep_tx_list) != NULL || 
		    vep->vep_tx_current || 
		    ((vep->vep_flags & VEP_FLG_CONNECTED) == 0)) {
			pfd->events |= POLLOUT;
		}

		/* accumulate timeouts:
		 * 1. connection establishment timeout
		 * 2. call timeouts
		 * 3. connection activity timeout
		 */
		ar_gettime(&cur);
	
		if ((vep->vep_flags & VEP_FLG_CONNECTED) == 0) {
			tspecsub(&vep->vep_estb_limit, &cur, &diff);
			period = ar_time_to_ms(&diff);
			if (period < timeout || timeout < 0) {
				timeout = period;
			}
		}

		if ((vep->vep_flags & VEP_FLG_CONNECTED) != 0 && 
		    (vep->vep_flags & VEP_FLG_IDLE_ENFORCE) != 0) {
			tspecadd(&vep->vep_svc_last_rx, 
				 &vep->vep_idle_period, &diff);
			tspecsub(&diff, &cur, &diff);
			period = ar_time_to_ms(&diff);
			if (period < timeout || timeout < 0) {
				timeout = period;
			}
		}

		TAILQ_FOREACH(cco, &ep->iep_clnt_calls, cco_listent) {
			tspecadd(&cco->cco_timeout, &cco->cco_start, &diff);
			tspecsub(&diff, &cur, &diff);
			period = ar_time_to_ms(&diff);
			if (period < timeout || timeout < 0) {
				timeout = period;
			}
		}

		*timeoutp = timeout;
		break;
	case VEP_TYPE_LISTENER:
		/* just always want POLLIN, done in this case. We
		 * don't use the kernel to flow control backlogged
		 * connections.  If we're over the limit we just want to 
		 * close them off so the other side knows we don't want them.
		 */
		pfd->events |= POLLIN;
		break;
	default:
		vc_queue_syserror(vep, EINVAL);
		*timeoutp = 0;
		return;
	}

	err = (*vep->vep_vcd->vcd_poll_setup)(vep->vep_stream, pfd, &timeout);
	if (err != 0 || pfd->fd < 0) {
		/* remember what happened.  We can't destroy ioep context
		 * in setup because it will mess up the core dispatch loop
		 */
		vc_queue_syserror(vep, err != 0 ? err : EINVAL);
		*timeoutp = 0;
		return;
	}

	if (timeout >= 0 && (timeout < *timeoutp || *timeoutp < 0)) {
		*timeoutp = timeout;
	}
}

static void
vc_dispatch(ar_ioep_t ep, struct pollfd *pfd)
{
	ar_clnt_call_obj_t cco;
	ar_clnt_call_obj_t cconext;
	ar_vcd_t vcd;
	vc_ioep_t *vep;
	ar_ioctx_t ioctx;
	struct timespec diff;
	struct timespec cur;
	struct timespec zero;
	arpc_err_t result;
	bool_t conn;
	int err;

	if (!pfd) {
		return;
	}

	if (!ep || ep->iep_type != IOEP_TYPE_VC) {
		return;
	}

	vep = ep->iep_drv_arg;
	if (!vep) {
		return;
	}

	if (vep->vep_sys_error > 0) {
		vc_syserror(vep, vep->vep_sys_error);
		return;
	}

	vcd = vep->vep_vcd;
	ioctx = ep->iep_ioctx;
	if (!ioctx) {
		vc_syserror(vep, EINVAL);
		return;
	}

	if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
		return;
	}

	vc_ioep_bumpref(ep);

	err = (*vcd->vcd_poll_dispatch)(vep->vep_stream, pfd);
	if (err != 0) {
		vc_syserror(vep, err);
		goto cleanup;
	}

	if (pfd->revents & (POLLERR|POLLNVAL)) {
		vc_syserror(vep, EIO);
		goto cleanup;
	}

	switch (vep->vep_type) {
	case VEP_TYPE_CONNECTION:
		if ((vep->vep_flags & VEP_FLG_CONNECTED) == 0) {
			err = (*vcd->vcd_control)(vep->vep_stream, 
						  AR_CLGET_CONNECTED, &conn);
			if (err == 0 && conn) {
				vep->vep_flags |= VEP_FLG_CONNECTED;
				vc_dispatch_connected(ep, ARPC_SUCCESS);
				if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
					goto cleanup;
				}
				ar_gettime(&cur);
				TAILQ_FOREACH(cco, &ep->iep_clnt_calls,
					      cco_listent) {
					cco->cco_start = cur;
				}
				vep->vep_svc_last_rx = cur;
			}
		}

		if (pfd->revents & POLLIN) {
			vc_read(ioctx, vep, ep);
			if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
				goto cleanup;
			}
		}

		vc_write(ioctx, vep, ep);

		if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
			goto cleanup;
		}

		/* dispatch timeouts:
		 * 1. connection establishment timeout
		 * 2. call timeouts
		 * 3. connection activity timeout
		 */
		ar_gettime(&cur);
		zero.tv_sec = 0;
		zero.tv_nsec = 0;

		if ((vep->vep_flags & VEP_FLG_CONNECTED) == 0) {
			tspecsub(&vep->vep_estb_limit, &cur, &diff);
			if (tspeccmp(&diff, &zero, <=)) {
				vc_dispatch_connected(ep, ARPC_TIMEDOUT);
				vc_syserror(vep, ETIMEDOUT);
				goto cleanup;
			}
		}

		if ((vep->vep_flags & VEP_FLG_CONNECTED) != 0 && 
		    (vep->vep_flags & VEP_FLG_IDLE_ENFORCE) != 0) {
			tspecadd(&vep->vep_svc_last_rx, 
				 &vep->vep_idle_period, &diff);
			tspecsub(&diff, &cur, &diff);
			if (tspeccmp(&diff, &zero, <=)) {
				vc_dispatch_disconnect(ep, ARPC_TIMEDOUT);
				vc_syserror(vep, ETIMEDOUT);
				goto cleanup;
			}
		}

		cco = TAILQ_FIRST(&ep->iep_clnt_calls);
		if (cco) {
			vc_cco_bumpref(cco);
		}
		for (; cco; cco = cconext) {
			cconext = TAILQ_NEXT(cco, cco_listent);
			if (cconext) {
				vc_cco_bumpref(cconext);
			}
			tspecadd(&cco->cco_timeout, &cco->cco_start, &diff);
			tspecsub(&diff, &cur, &diff);
			if (tspeccmp(&diff, &zero, >)) {
				vc_cco_dropref(cco);
				continue;
			}
			if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
				cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
				vc_cco_dropref(cco); /* release user ref */
				cco->cco_rpc_err.re_status = ARPC_TIMEDOUT;
				result = cco->cco_rpc_err;
				(*cco->cco_cb)(cco, cco->cco_cb_arg, 
					       &result, NULL);
			}
			vc_cco_destroy(cco);
			vc_cco_dropref(cco);
		}

		break;
	case VEP_TYPE_LISTENER: {
		void *stream;
		ar_svc_attr_t attr;
		vc_ioep_t *vep2;
		ar_ioep_t ioep2;
		void *arg;
		ar_svc_xprt_t *xp;

		ar_svc_attr_init(&attr);
		attr.sa_sendsz = vep->vep_sendsz;
		attr.sa_recvsz = vep->vep_recvsz;

		/* child connections inherit initial debug config from
		 * listener.
		 */
		ar_svc_attr_set_debug(&attr, ep->iep_debug_file, 
				      ep->iep_debug_prefix);

		/* accept new server endpoints */
		while ((pfd->revents & POLLIN) != 0) {
			err = (*vcd->vcd_accept)(vep->vep_stream, &stream);
			if (err == EAGAIN) {
				/* no more connections */
				break;
			}

			if (err != 0) {
				/* some bad error */
				/* do we really want to destroy the listener?
				 * how does the app know we did this? 
				 * FIXME:
				 */
				vc_syserror(vep, err);
				break;
			}

			if ((vep->vep_flags & VEP_FLG_FLOWCTL) != 0) {
				/* over our limit.  Just destroy the conn */
				(*vcd->vcd_destroy)(stream);
				continue;
			}

			if (vcd->vcd_gettmout) {
				err = (*vcd->vcd_gettmout)(vep->vep_stream,
							   &attr.sa_create_tmout);
				if (err != EOK) {
					(*vcd->vcd_destroy)(stream);
					continue;
				}
			}

			/* create xp context */
			err = ar_svc_vc_create(ioctx, vcd, stream, 
					       &attr, NULL, &xp);
			if (err != 0) {
				/* unable to handle connection. close it
				 * down.
				 */
				(*vcd->vcd_destroy)(stream);
			} else {
				assert(xp != NULL);

				/* flag ioep as from listener */
				ioep2 = xp->xp_ioep;
				assert(ioep2 != NULL);
				
				vc_xp_bumpref(xp);

				vep2 = ioep2->iep_drv_arg;

				vep2->vep_flags |= VEP_FLG_FROM_LISTEN;

				/* update flow control on listener. We
				 * don't want to many fd's 
				 */
				vc_update_flowctl(vep);

				/* notify application of new connection. */
				if (vep->vep_accept_cb) {
					arg = vep->vep_accept_arg;
					err = (*vep->vep_accept_cb)(ioctx, xp,
								    arg);
				} else {
					err = 0;
				}

				/* release user reference to xp. We have 
				 * control of destruction of non-listen
				 * server contexts.
				 */
				if (err != EOK) {
					/* need to destroy new connection */
					ar_svc_destroy(xp);
				}
				if ((xp->xp_flags & XP_FLG_USRREF_DEC) == 0) {
					xp->xp_flags |= XP_FLG_USRREF_DEC;
					vc_xp_dropref(xp);
				}
				vc_xp_dropref(xp);
			}
		}
		break;
	}
	default:
		vc_syserror(vep, EINVAL);
	}

 cleanup:
	vc_ioep_dropref(ep);
}

static void
vc_destroy(ar_ioep_t ep)
{
	vc_ioep_destroy(ep);
}

static void
vc_sendmsg_done(void *arg, int err)
{
	vep_tx_obj_t	*txo;

	txo = (vep_tx_obj_t *)arg;
	assert(txo != NULL);

	if (txo->to_data.to_buffer.buf) {
		free(txo->to_data.to_buffer.buf);
	}
	txo->to_data.to_buffer.buf = NULL;
	txo->to_data.to_buffer.len = 0;

	free(txo);
}

static int
vc_sendmsg(ar_ioep_t ep, arpc_msg_t *msg, ar_svc_call_obj_t sco)
{
	vep_tx_obj_t	*txo;
	int		len;
	char		*buf;
	axdr_ret_t	ret;
	axdr_state_t		axdr;
	vc_ioep_t	*vep;

	if (!ep || !msg) {
		return EINVAL;
	}

	if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
		return EIO;
	}

	vep = (vc_ioep_t *)ep->iep_drv_arg;
	if (!vep) {
		return EINVAL;
	}

	txo = malloc(sizeof(*txo));
	if (!txo) {
		return ENOMEM;
	}
	memset(txo, 0, sizeof(*txo));
	
	len = axdr_sizeof((axdrproc_t)&axdr_msg, msg);
	buf = malloc(len);
	if (!buf) {
		free(txo);
		return ENOMEM;
	}

	axdrmem_create(&axdr, buf, len, AXDR_ENCODE);
	ret = axdr_msg(&axdr, msg);
	axdr_destroy(&axdr);

	if (ret != AXDR_DONE) {
		free(buf);
		free(txo);
		return EPARSE;
	}

	txo->to_type = VEP_TX_TYPE_BUF;
	txo->to_msgtype = VEP_MSGTYPE_SYNC_REPLY;
	txo->to_flags = TO_FLG_HI_PRIO;
	txo->to_data.to_buffer.buf = buf;
	txo->to_data.to_buffer.len = len;
	txo->to_size = len;
	txo->to_opaque = txo;
	txo->to_done = &vc_sendmsg_done;

	TAILQ_INSERT_TAIL(&vep->vep_tx_list, txo, to_listent);
	vc_update_flowctl(vep);

	return 0;
}


static int
vc_add_client(ar_ioep_t ep, const arpcprog_t prog, const arpcvers_t vers,
	      ar_clnt_attr_t *attr, arpc_err_t *errp,
	      ar_client_t **retp)
{
	ar_clnt_attr_t	lattr;
	vc_ioep_t	*vep;
	ar_client_t	*cl;
	ar_stat_t	status;
	int		err;

	status = ARPC_SUCCESS;

	if (!ep || !retp) {
		status = ARPC_ERRNO;
		err = EINVAL;
		goto error;
	}

	if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
		status = ARPC_INTR;
		err = EIO;
		goto error;
	}

	if (!attr) {
		err = ar_clnt_attr_init(&lattr);
		if (err != 0) {
			status = ARPC_ERRNO;
			err = EINVAL;
			goto error;
		}
		attr = &lattr;
	}

	vep = (vc_ioep_t *)ep->iep_drv_arg;

	/* create the client */
	cl = malloc(sizeof(*cl));
	if (!cl) {
		status = ARPC_ERRNO;
		err = ENOMEM;
		goto error;
	}
	memset(cl, 0, sizeof(*cl));

	cl->cl_refcnt = vep->vep_iref_val + 1;
	cl->cl_ops = &vc_clnt_ops;
	cl->cl_ioep = ep;
	cl->cl_ioctx = ep->iep_ioctx;
	cl->cl_prog = prog;
	cl->cl_ver = vers;
	cl->cl_private = vep;
	cl->cl_defwait.tv_sec = CG_DEF_RPC_TIMEOUT_SECS;
	cl->cl_defwait.tv_nsec = CG_DEF_RPC_TIMEOUT_NSECS;
	cl->cl_queued_err = -1;

	if (attr && (attr->ca_flags & CA_FLG_REQUIRED) != 0) {
		cl->cl_flags |= CLNT_FLG_KILL_SVC;
	}

	/* FIXME: we need a per client private structure.  These should
	 * be in there...
	 */
	cl->cl_conn_cb = attr->ca_conn_cb;
	cl->cl_conn_cb_arg = attr->ca_conn_arg;
	cl->cl_discon_cb = attr->ca_discon_cb;
	cl->cl_discon_cb_arg = attr->ca_discon_arg;

	/* add client to ep */
	TAILQ_INSERT_TAIL(&ep->iep_client_list, cl, cl_listent);

	/* return client */
	*retp = cl;
	err = 0;

	if (cl->cl_conn_cb && (vep->vep_flags & VEP_FLG_CONNECTED) != 0) {
		arpc_createerr_t cerr;
		memset(&cerr, 0, sizeof(cerr));
		cerr.cf_stat = ARPC_SUCCESS;
		(*cl->cl_conn_cb)(cl, cl->cl_conn_cb_arg, &cerr);
	}

 error:
	if (attr == &lattr) {
		ar_clnt_attr_destroy(&lattr);
	}
	if (errp) {
		errp->re_status = status;
		if (status == ARPC_ERRNO) {
			errp->re_errno = err;
		}
	}
		
	return err;
}

#ifdef HAVE_LIBEVENT
/* vc_event_cb() is a callback function from the event.
 * it is very similar to vc_dispatch().
 */
static void
vc_event_cb(evutil_socket_t fd, short events, void *arg)
{
	ar_clnt_call_obj_t cco;
	ar_clnt_call_obj_t cconext;
	ar_ioep_t ep;
	ar_ioctx_t ioctx;
	vc_ioep_t *vep;
	ar_vcd_t vcd;
	struct timespec diff;
	struct timespec cur;
	struct timespec zero;
	arpc_err_t result;
	bool_t conn;
	struct pollfd pfd;
	int err;

	ep = (ar_ioep_t)arg;
	if (!ep || ep->iep_type != IOEP_TYPE_VC) {
		return;
	}

	vep = ep->iep_drv_arg;
	if (vep == NULL) {
		return;
	}

	if (vep->vep_sys_error > 0) {
		vc_syserror(vep, vep->vep_sys_error);
		return;
	}

	vcd = vep->vep_vcd;
	ioctx = ep->iep_ioctx;
	if (!ioctx) {
		vc_syserror(vep, EINVAL);
		return;
	}

	if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
		return;
	}

	vc_ioep_bumpref(ep);

	RPCTRACE(ioctx, 3, "vc_event_cb(): fd %d, events %d, ep %p\n",
		 fd, events, ep);

	/* convert the callback events into pfd */
	memset(&pfd, 0, sizeof(pfd));
	err = (*vcd->vcd_get_fd)(vep->vep_stream, &pfd.fd);
	if (err != 0) {
		fprintf(stderr, "Failed to get vcd fd\n");
		vc_syserror(vep, err);
		goto cleanup;
	}
	if (events & EV_READ) {
		pfd.revents |= POLLIN;
	}
	if (events & EV_WRITE) {
		pfd.revents |= POLLOUT;
	}
	err = (*vcd->vcd_poll_dispatch)(vep->vep_stream, &pfd);
	if (err != 0) {
		vc_syserror(vep, err);
		goto cleanup;
	}

	switch (vep->vep_type) {
	case VEP_TYPE_CONNECTION:
		if ((vep->vep_flags & VEP_FLG_CONNECTED) == 0) {
			err = (*vcd->vcd_control)(vep->vep_stream, 
						  AR_CLGET_CONNECTED, &conn);
			if (err == 0 && conn) {
				vep->vep_flags |= VEP_FLG_CONNECTED;
				vc_dispatch_connected(ep, ARPC_SUCCESS);
				if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
					goto cleanup;
				}
				ar_gettime(&cur);
				TAILQ_FOREACH(cco, &ep->iep_clnt_calls,
					      cco_listent) {
					cco->cco_start = cur;
				}
				vep->vep_svc_last_rx = cur;
			}
		}

		if (events & EV_READ) {
			vc_read(ioctx, vep, ep);
			if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
				goto cleanup;
			}
		}

		vc_write(ioctx, vep, ep);

		if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
			goto cleanup;
		}

		/* dispatch timeouts:
		 * 1. connection establishment timeout
		 * 2. call timeouts
		 * 3. connection activity timeout
		 */
		ar_gettime(&cur);
		zero.tv_sec = 0;
		zero.tv_nsec = 0;

		if ((vep->vep_flags & VEP_FLG_CONNECTED) == 0) {
			tspecsub(&vep->vep_estb_limit, &cur, &diff);
			if (tspeccmp(&diff, &zero, <=)) {
				vc_dispatch_connected(ep, ARPC_TIMEDOUT);
				vc_syserror(vep, ETIMEDOUT);
				goto cleanup;
			}
		}

		if ((vep->vep_flags & VEP_FLG_CONNECTED) != 0 && 
		    (vep->vep_flags & VEP_FLG_IDLE_ENFORCE) != 0) {
			tspecadd(&vep->vep_svc_last_rx, 
				 &vep->vep_idle_period, &diff);
			tspecsub(&diff, &cur, &diff);
			if (tspeccmp(&diff, &zero, <=)) {
				vc_dispatch_disconnect(ep, ARPC_TIMEDOUT);
				vc_syserror(vep, ETIMEDOUT);
				goto cleanup;
			}
		}

		cco = TAILQ_FIRST(&ep->iep_clnt_calls);
		if (cco) {
			vc_cco_bumpref(cco);
		}
		for (; cco; cco = cconext) {
			cconext = TAILQ_NEXT(cco, cco_listent);
			if (cconext) {
				vc_cco_bumpref(cconext);
			}
			tspecadd(&cco->cco_timeout, &cco->cco_start, &diff);
			tspecsub(&diff, &cur, &diff);
			if (tspeccmp(&diff, &zero, >)) {
				vc_cco_dropref(cco);
				continue;
			}
			if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
				cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
				vc_cco_dropref(cco); /* release user ref */
				cco->cco_rpc_err.re_status = ARPC_TIMEDOUT;
				result = cco->cco_rpc_err;
				(*cco->cco_cb)(cco, cco->cco_cb_arg, 
					       &result, NULL);
			}
			vc_cco_destroy(cco);
			vc_cco_dropref(cco);
		}

		break;

	case VEP_TYPE_LISTENER: {
		void *stream;
		ar_svc_attr_t attr;
		vc_ioep_t *vep2;
		ar_ioep_t ioep2;
		void *accept_arg;
		ar_svc_xprt_t *xp;
		struct event *ev;
		struct event_base *event_base;
		
		ar_svc_attr_init(&attr);
		attr.sa_sendsz = vep->vep_sendsz;
		attr.sa_recvsz = vep->vep_recvsz;

		/* child connections inherit initial debug config from
		 * listener.
		 */
		ar_svc_attr_set_debug(&attr, ep->iep_debug_file, 
				      ep->iep_debug_prefix);

		if (events & EV_READ) {
			/* new connection */
			err = (*vcd->vcd_accept)(vep->vep_stream, &stream);
			if (err == EAGAIN) {
				/* no more connections */
				break;
			}

			if (err != 0) {
				/* some bad error */
				/* do we really want to destroy the listener?
				 * how does the app know we did this? 
				 * FIXME:
				 */
				vc_syserror(vep, err);
				break;
			}

			if ((vep->vep_flags & VEP_FLG_FLOWCTL) != 0) {
				/* over our limit.  Just destroy the conn */
				(*vcd->vcd_destroy)(stream);
				break;;
			}

			if (vcd->vcd_gettmout) {
				err = (*vcd->vcd_gettmout)(vep->vep_stream,
							   &attr.sa_create_tmout);
				if (err != EOK) {
					(*vcd->vcd_destroy)(stream);
					break;
				}
			}

			/* create xp context */
			err = ar_svc_vc_create(ioctx, vcd, stream, 
					       &attr, NULL, &xp);
			if (err != 0) {
				/* unable to handle connection. close it
				 * down.
				 */
				(*vcd->vcd_destroy)(stream);
			} else {
				assert(xp != NULL);

				/* flag ioep as from listener */
				ioep2 = xp->xp_ioep;
				assert(ioep2 != NULL);
				
				vc_xp_bumpref(xp);

				vep2 = ioep2->iep_drv_arg;

				vep2->vep_flags |= VEP_FLG_FROM_LISTEN;

				/* update flow control on listener. We
				 * don't want to many fd's 
				 */
				vc_update_flowctl(vep);

				/* notify application of new connection. */
				if (vep->vep_accept_cb) {
					accept_arg = vep->vep_accept_arg;
					err = (*vep->vep_accept_cb)(ioctx, xp,
								    accept_arg);
				} else {
					err = 0;
				}

				/* release user reference to xp. We have 
				 * control of destruction of non-listen
				 * server contexts.
				 */
				if (err != EOK) {
					/* need to destroy new connection */
					ar_svc_destroy(xp);
				}
				if ((xp->xp_flags & XP_FLG_USRREF_DEC) == 0) {
					xp->xp_flags |= XP_FLG_USRREF_DEC;
					vc_xp_dropref(xp);
				}
				vc_xp_dropref(xp);

				err = (*vep2->vep_vcd->vcd_get_fd)
				    (vep2->vep_stream, &fd);
				if (err != 0) {
					/* bailout */
					ar_svc_destroy(xp);
				}
				/* create and setup event object */
				event_base = event_get_base(ep->iep_event);
				if (event_base == NULL) {
					fprintf(stderr,
						"Cannot get the event_base\n");
					ar_svc_destroy(xp);
				}
				ev = event_new(event_base, fd,
					       EV_PERSIST | EV_READ,
					       vc_event_cb, (void *)ioep2);
				/* monitor the event */
				if (ev == NULL) {
					fprintf(stderr,
						"Cannot create an event\n");
					ar_svc_destroy(xp);
				}
				event_add(ev, NULL);
				ioep2->iep_event = ev;

				RPCTRACE(ioctx, 3,
					 "New connection(): fd %d, ep %p\n",
					 fd, ioep2);
			}
		}
		break;
	}
	default:
		vc_syserror(vep, EINVAL);
	}
	    
 cleanup:
	vc_ioep_dropref(ep);
}

static int
vc_event_setup(ar_ioep_t ep, struct event_base *evbase)
{
	struct pollfd pfd;
	struct event *ev;
	short events;
	struct timespec ts;
	struct timeval tv;
	int timeout;
	int err;

	if (!ep || ep->iep_type != IOEP_TYPE_VC) {
		return EINVAL;
	}

	/* If an event is active, remove the event from monitored list */
	if (ep->iep_event) {
		event_del(ep->iep_event);
	}

	/* call poll_setup routine for the fd and events */
	memset(&pfd, 0, sizeof(pfd));
	vc_setup(ep, &pfd, &timeout);

	ar_gettime(&ts);
	ar_tsaddmsecs(&ts, timeout);

	/* convert pollfd's events into libevent events */
	events = EV_PERSIST;
	if (pfd.events & POLLIN) {
		events |= EV_READ;
	}
	if (pfd.events & POLLOUT) {
		events |= EV_WRITE;
	}
	
	/* create and setup event object */
	if (ep->iep_event == NULL) {
		ev = event_new(evbase, (evutil_socket_t)pfd.fd,
			       events, vc_event_cb, (void *)ep);
		if (ev == NULL) {
			return ENOMEM;
		}
		ep->iep_event = ev;
	} else {
		err = event_assign(ep->iep_event, evbase,
				   (evutil_socket_t)pfd.fd,
				   events, vc_event_cb, (void *)ep);
		if (err != 0) {
			event_free(ep->iep_event);
			ep->iep_event = NULL;
			return EINVAL;
		}
	}
	/* monitor the event */
	tv.tv_sec = ts.tv_sec;
	tv.tv_usec = ts.tv_nsec / 1000;
	event_add(ep->iep_event, &tv);

	RPCTRACE(ep->iep_ioctx, 3, "vc_event_setup(): fd %d ep %p\n",
		 pfd.fd, ep);
	
	return 0;
}
#endif /* HAVE_LIBEVENT */

static int
vcd_err(void)
{
	return ENXIO;
}

int
ar_vcd_create(ar_vcd_t *retp)
{
	ar_vcd_t vcd;
	
	if (!retp) {
		return EINVAL;
	}

	vcd = malloc(sizeof(*vcd));
	if (!vcd) {
		return ENOMEM;
	}

	memset(vcd, 0, sizeof(*vcd));
	vcd->vcd_read = (ar_vcd_readfn_t)vcd_err;
	vcd->vcd_write = (ar_vcd_writefn_t)vcd_err;
	vcd->vcd_close = (ar_vcd_closefn_t)vcd_err;
	vcd->vcd_shutdown = (ar_vcd_closefn_t)vcd_err;
	vcd->vcd_control = (ar_vcd_cntrlfn_t)vcd_err;
	vcd->vcd_poll_setup = (ar_vcd_psetupfn_t)vcd_err;
	vcd->vcd_poll_dispatch = (ar_vcd_pdispatchfn_t)vcd_err;
	vcd->vcd_get_fd = (ar_vcd_getfdfn_t)vcd_err;
	vcd->vcd_from_fd = (ar_vcd_fromfd_t)vcd_err;
	vcd->vcd_connect = (ar_vcd_connfn_t)vcd_err;
	vcd->vcd_accept = (ar_vcd_accept_t)vcd_err;
	vcd->vcd_getladdr = (ar_vcd_getladdr_t)vcd_err;
	vcd->vcd_getfamily = (ar_vcd_getfamily_t)vcd_err;
	vcd->vcd_islistener = (ar_vcd_islistener_t)vcd_err;
	vcd->vcd_listen = (ar_vcd_listen_t)vcd_err;
	vcd->vcd_init = (ar_vcd_init_t)vcd_err;
	vcd->vcd_destroy = (ar_vcd_destroy_t)vcd_err;

	*retp = vcd;
	return 0;
}

void
ar_vcd_destroy(ar_vcd_t vcd)
{
	if (vcd) {
		free(vcd);
	}
}

int
ar_vcd_set_write(ar_vcd_t vcd, ar_vcd_writefn_t writefn)
{
	if (!vcd || !writefn) {
		return EINVAL;
	}

	vcd->vcd_write = writefn;
	return 0;
}
	
int
ar_vcd_set_read(ar_vcd_t vcd, ar_vcd_readfn_t readfn)
{
	if (!vcd || !readfn) {
		return EINVAL;
	}

	vcd->vcd_read = readfn;
	return 0;
}

int
ar_vcd_set_close(ar_vcd_t vcd, ar_vcd_closefn_t closefn)
{
	if (!vcd || !closefn) {
		return EINVAL;
	}

	vcd->vcd_close = closefn;
	return 0;
}

int
ar_vcd_set_control(ar_vcd_t vcd, ar_vcd_cntrlfn_t controlfn)
{
	if (!vcd || !controlfn) {
		return EINVAL;
	}

	vcd->vcd_control = controlfn;
	return 0;
}

int
ar_vcd_set_connect(ar_vcd_t vcd, ar_vcd_connfn_t connfn)
{
	if (!vcd || !connfn) {
		return EINVAL;
	}

	vcd->vcd_connect = connfn;
	return 0;
}

int
ar_vcd_set_shutdown(ar_vcd_t vcd, ar_vcd_closefn_t shutdownfn)
{
	if (!vcd || !shutdownfn) {
		return EINVAL;
	}

	vcd->vcd_shutdown = shutdownfn;
	return 0;
}

int
ar_vcd_set_pollsetup(ar_vcd_t vcd, ar_vcd_psetupfn_t psetup)
{
	if (!vcd || !psetup) {
		return EINVAL;
	}

	vcd->vcd_poll_setup = psetup;
	return 0;
}

int
ar_vcd_set_polldispatch(ar_vcd_t vcd, ar_vcd_pdispatchfn_t pdispatch)
{
	if (!vcd || !pdispatch) {
		return EINVAL;
	}

	vcd->vcd_poll_dispatch = pdispatch;
	return 0;
}

int
ar_vcd_set_getfd(ar_vcd_t vcd, ar_vcd_getfdfn_t getfd)
{
	if (!vcd || !getfd) {
		return EINVAL;
	}

	vcd->vcd_get_fd = getfd;
	return 0;
}

int
ar_vcd_set_fromfd(ar_vcd_t vcd, ar_vcd_fromfd_t fromfd)
{
	if (!vcd || !fromfd) {
		return EINVAL;
	}

	vcd->vcd_from_fd = fromfd;
	return 0;
}

int
ar_vcd_set_accept(ar_vcd_t vcd, ar_vcd_accept_t acceptfn)
{
	if (!vcd || !acceptfn) {
		return EINVAL;
	}

	vcd->vcd_accept = acceptfn;
	return 0;
}

int
ar_vcd_set_init(ar_vcd_t vcd, ar_vcd_init_t initfn)
{
	if (!vcd || !initfn) {
		return EINVAL;
	}

	vcd->vcd_init = initfn;
	return 0;
}

int
ar_vcd_set_destroy(ar_vcd_t vcd, ar_vcd_destroy_t fn)
{
	if (!vcd || !fn) {
		return EINVAL;
	}

	vcd->vcd_destroy = fn;
	return 0;
}

int
ar_vcd_set_getladdr(ar_vcd_t vcd, ar_vcd_getladdr_t fn)
{
	if (!vcd || !fn) {
		return EINVAL;
	}

	vcd->vcd_getladdr = fn;
	return 0;
}

int
ar_vcd_set_getfamily(ar_vcd_t vcd, ar_vcd_getfamily_t fn)
{
	if (!vcd || !fn) {
		return EINVAL;
	}

	vcd->vcd_getfamily = fn;
	return 0;
}

int
ar_vcd_set_islistener(ar_vcd_t vcd, ar_vcd_islistener_t fn)
{
	if (!vcd || !fn) {
		return EINVAL;
	}

	vcd->vcd_islistener = fn;
	return 0;
}

int
ar_vcd_set_listen(ar_vcd_t vcd, ar_vcd_listen_t fn)
{
	if (!vcd || !fn) {
		return EINVAL;
	}

	vcd->vcd_listen = fn;
	return 0;
}

static int
vcd_dflt_read(void *vc, struct iovec *vector, int count, size_t *lenp)
{
	vcd_dflt_ctx_t *ctx;
	ssize_t ret;
	int err;
	char *cp;
	size_t len;
	size_t accum;
	void *orig_base = NULL;
	int orig_len = -1;
	int i;

	if (!vc || !lenp || !vector) {
		return EINVAL;
	}
	ctx = (vcd_dflt_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
	default:
		return ENOTCONN;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
		return EAGAIN;
	case VCDD_STATE_SHUTDOWN:
	case VCDD_STATE_ESTABLISHED:
		break;
	}

	if (count <= 0) {
		*lenp = 0;
		return 0;
	}

	i = 0;
	accum = 0;

	/* copy buffered data first */
	while (ctx->vdc_bufcnt > 0) {
		len = vector[i].iov_len;
		if (len > ctx->vdc_bufcnt) {
			len = ctx->vdc_bufcnt;
		}
		memcpy(vector[i].iov_base, ctx->vdc_buf, len);
		if ((ctx->vdc_bufcnt - len) > 0) {
			memmove(ctx->vdc_buf, &ctx->vdc_buf[len], 
				ctx->vdc_bufcnt - len);
		}
		ctx->vdc_bufcnt -= len;
		accum += len;
		if (len >= vector[i].iov_len) {
			if (orig_base) {
				vector[i].iov_base = orig_base;
				vector[i].iov_len = orig_len;
				orig_base = NULL;
				orig_len = -1;
			}
			i++;
			if (i >= count) {
				*lenp = accum;
				return 0;
			}
		} else {
			if (!orig_base) {
				orig_base = vector[i].iov_base;
				orig_len = vector[i].iov_len;
			}
			vector[i].iov_len -= len;
			cp = vector[i].iov_base;
			vector[i].iov_base = &cp[len];
		}
	}

	ret = readv(ctx->vdc_fd, &vector[i], count - i);
	if (orig_base) {
		vector[i].iov_base = orig_base;
		vector[i].iov_len = orig_len;
	}

	if (ret < 0) {
		*lenp = accum;
		if (accum > 0) {
			/* we got data. Have to indicate that */
			err = 0;
		} else {
			err = errno;
		}
	} else {
		*lenp = (size_t)ret + accum;
		err = 0;
	}

	return err;
}

static int
vcd_dflt_write(void *vc, const struct iovec *vector, int count, size_t *lenp)
{
	vcd_dflt_ctx_t *ctx;
	ssize_t ret;
	int err;

	if (!vc || !lenp || !vector) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
	default:
		return ENOTCONN;
	case VCDD_STATE_SHUTDOWN:
		return EPIPE;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
		return EAGAIN;
	case VCDD_STATE_ESTABLISHED:
		break;
	}

	if (count <= 0) {
		*lenp = 0;
		return 0;
	}

	ret = writev(ctx->vdc_fd, vector, count);
	if (ret < 0) {
		*lenp = 0;
		err = errno;
	} else {
		*lenp = (size_t)ret;
		err = 0;
	}
	return err;
}

static int
vcd_dflt_close(void *vc)
{
	vcd_dflt_ctx_t *ctx;
	int ret;
	
	if (!vc) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
		return 0;
	default:
		return EIO;
	case VCDD_STATE_SHUTDOWN:
	case VCDD_STATE_CONNECTING:
	case VCDD_STATE_ESTABLISHED:
	case VCDD_STATE_LISTEN:
		ret = close(ctx->vdc_fd);
		if (ret < 0) {
			ret = errno;
		} else {
			ret = 0;
		}
		ctx->vdc_fd = -1;
		ctx->vdc_state = VCDD_STATE_CLOSED;
		return ret;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	}
}

static int
vcd_dflt_shutdown(void *vc)
{
	vcd_dflt_ctx_t *ctx;
	int ret;
	
	if (!vc) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
	default:
		return ENOTCONN;
	case VCDD_STATE_SHUTDOWN:
		return 0;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
	case VCDD_STATE_ESTABLISHED:
		ret = shutdown(ctx->vdc_fd, SHUT_WR);
		if (ret < 0) {
			ret = errno;
		} else {
			ret = 0;
		}

		ctx->vdc_state = VCDD_STATE_SHUTDOWN;

		return ret;
	}
}

static int
vcd_dflt_control(void *vc, u_int request, void *info)
{
	vcd_dflt_ctx_t *ctx;
	arpc_addr_t *nb;
	int err;
	
	if (!vc) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;
	switch (request) {
	case AR_CLGET_CONNECTED: {
		bool_t conn;

		if (!info) {
			return EINVAL;
		}

		switch (ctx->vdc_state) {
		case VCDD_STATE_CLOSED:
		case VCDD_STATE_SHUTDOWN:
		case VCDD_STATE_ERROR:
		case VCDD_STATE_CONNECTING:
		default:
			conn = FALSE;
			break;
		case VCDD_STATE_ESTABLISHED:
			conn = TRUE;
		}

		*((bool_t *)info) = conn;
		return 0;
	}
	case AR_CLGET_SERVER_ADDR:
		if (!info) {
			return EINVAL;
		}

		nb = (arpc_addr_t *)info;
		nb->len = nb->maxlen;
		err = getpeername(ctx->vdc_fd, (struct sockaddr *)nb->buf,
				  &nb->len);
		if (err < 0) {
			err = errno;
		} else {
			err = 0;
		}
		return err;
	case AR_CLGET_LOCAL_ADDR:
		if (!info) {
			return EINVAL;
		}

		nb = (arpc_addr_t *)info;
		nb->len = nb->maxlen;
		err = getsockname(ctx->vdc_fd, (struct sockaddr *)nb->buf,
				  &nb->len);
		if (err < 0) {
			err = errno;
		} else {
			err = 0;
		}
		return err;
	default:
		return ENOSYS;
	}
}

static int
vcd_dflt_poll_setup(void *vc, struct pollfd *pfd, int *timeoutp)
{
	vcd_dflt_ctx_t *ctx;
	
	if (!vc || !pfd || !timeoutp) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;

	pfd->fd = (int)ctx->vdc_fd;
	*timeoutp = -1;

	/* save off original requested events. */
	ctx->vdc_events = pfd->events;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
		pfd->fd = -1;
		pfd->events = 0;
		return 0;
	default:
		pfd->fd = -1;
		return ENOTCONN;
	case VCDD_STATE_SHUTDOWN:
		pfd->events &= ~POLLOUT;
		return 0;
	case VCDD_STATE_ERROR:
		pfd->fd = -1;
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
		pfd->events |= POLLOUT|POLLIN;
		return 0;
	case VCDD_STATE_ESTABLISHED:
	case VCDD_STATE_LISTEN:
		return 0;
	}
}

static int
vcd_dflt_poll_dispatch(void *vc, struct pollfd *pfd)
{
	vcd_dflt_ctx_t *ctx;
	int rval;
	
	if (!vc || !pfd) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
		return 0;
	default:
		return ENOTCONN;
	case VCDD_STATE_SHUTDOWN:
		return 0;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
		/* restore user's requested events */
		pfd->events = ctx->vdc_events;
		if ((pfd->revents & POLLOUT) != 0) {
			ctx->vdc_state = VCDD_STATE_ESTABLISHED;
			pfd->revents = ((pfd->revents & ~(POLLIN|POLLOUT)) |
					(pfd->revents & ctx->vdc_events));
			return 0;
		}
		if ((pfd->revents & POLLIN) != 0) {
			/* probably some error value.  Try to get it */
			rval = read(ctx->vdc_fd, ctx->vdc_buf, 1);
			if (rval == 1) {
				ctx->vdc_state = VCDD_STATE_ESTABLISHED;
				ctx->vdc_bufcnt = 1;
			} else {
				if (rval == 0) {
					/* connection closed */
					rval = ENOTCONN;
				} else {
					rval = errno;
					if (rval == 0) {
						rval = EIO;
					}
				}
				ctx->vdc_state = VCDD_STATE_ERROR;
				ctx->vdc_err = rval;
				ctx->vdc_events = 0;
				close(ctx->vdc_fd);
				ctx->vdc_fd = -1;
				return rval;
			}
			pfd->revents = ((pfd->revents & ~(POLLIN|POLLOUT)) |
					(pfd->revents & ctx->vdc_events));
			return 0;
		}
		return 0;
	case VCDD_STATE_ESTABLISHED:
	case VCDD_STATE_LISTEN:
		return 0;
	}
}

static int
vcd_dflt_getfd(void *vc, int *fdp)
{
	vcd_dflt_ctx_t *ctx;
	
	if (!vc || !fdp) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
	default:
		return ENOTCONN;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	case VCDD_STATE_SHUTDOWN:
	case VCDD_STATE_CONNECTING:
	case VCDD_STATE_ESTABLISHED:
	case VCDD_STATE_LISTEN:
		*fdp = ctx->vdc_fd;
		return 0;
	}
}

static int
vcd_dflt_fromfd(ar_svc_attr_t *svc_attr, int fd, void **vcp)
{
	vcd_dflt_ctx_t *ctx;
	struct sockaddr_storage ss;
	socklen_t len;
	void *vc;
	int flags;
	int err;

	/* FIXME: is there a way to check if this is SOCK_STREAM?
	 * we rely on the remote addr to determine if the socket is a
	 * listener or not.  That is not entirely foolproof either.
	 */

	/* make sure it's in non-block mode */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return errno;
	}
	flags |= O_NONBLOCK|O_NDELAY;
	err = fcntl(fd, F_SETFL, flags);
	if (err != 0) {
		return errno;
	}

	/* close on exec */
	err = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (err != 0) {
		return errno;
	}

	err = vcd_dflt_init(NULL, NULL, &vc);
	if (err != EOK) {
		return err;
	}
	ctx = (vcd_dflt_ctx_t *)vc;

	len = sizeof(ss);
	err = getpeername(fd, (struct sockaddr *)&ss, &len);
	if (err == 0) {
		/* Connected  */
		ctx->vdc_state = VCDD_STATE_ESTABLISHED;
	} else {
		ctx->vdc_state = VCDD_STATE_LISTEN;
	}

	ctx->vdc_fd = fd;
	ctx->vdc_bufcnt = 0;

	*vcp = vc;
	return 0;
}

static int
vcd_dflt_conn(void *vc, const arpc_addr_t *na, arpc_createerr_t *errp)
{
	vcd_dflt_ctx_t *ctx;
	struct sockaddr *sa;
	int flags;
	int ret;

	if (!vc || !na) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;

	if (na->len < sizeof(*sa)) {
		return vc_syscreat_err(errp, EINVAL);
	}
	sa = (struct sockaddr *)na->buf;
	switch (sa->sa_family) {
	case AF_INET:
		if (na->len < sizeof(struct sockaddr_in)) {
			return vc_syscreat_err(errp, EINVAL);
		}
		break;
	case AF_INET6:
		if (na->len < sizeof(struct sockaddr_in6)) {
			return vc_syscreat_err(errp, EINVAL);
		}
		break;
	case AF_LOCAL:
		if (na->len < sizeof(struct sockaddr_un)) {
			return vc_syscreat_err(errp, EINVAL);
		}
		break;
	default:
		return vc_syscreat_err(errp, EINVAL);
	}

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
		ret = socket(sa->sa_family, SOCK_STREAM, 0);
		if (ret < 0) {
			ctx->vdc_state = VCDD_STATE_ERROR;
			ctx->vdc_err = errno;
			return vc_syscreat_err(errp, errno);
		}
		ctx->vdc_fd = ret;

		/* nonblock */
		flags = fcntl(ctx->vdc_fd, F_GETFL, 0);
		if (flags == -1) {
			ret = errno;
			goto error;
		}
		flags |= O_NONBLOCK|O_NDELAY;
		ret = fcntl(ctx->vdc_fd, F_SETFL, flags);
		if (ret != 0) {
			ret = errno;
			goto error;
		}

		/* close on exec */
		ret = fcntl(ctx->vdc_fd, F_SETFD, FD_CLOEXEC);
		if (ret != 0) {
			ret = errno;
			goto error;
		}

		ret = connect(ctx->vdc_fd, sa, na->len);
		if (ret < 0) {
			ret = errno;
			if (ret != EINPROGRESS) {
				goto error;
			}
			ctx->vdc_state = VCDD_STATE_CONNECTING;
		} else {
			ctx->vdc_state = VCDD_STATE_ESTABLISHED;
		}
		return 0;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
	case VCDD_STATE_SHUTDOWN:
	case VCDD_STATE_ESTABLISHED:
		return EBUSY;
	default:
		return EINVAL;
	}

 error:
	close(ctx->vdc_fd);
	ctx->vdc_fd = -1;
	ctx->vdc_err = ret;
	ctx->vdc_state = VCDD_STATE_ERROR;
	return vc_syscreat_err(errp, ret);
}


static int
vcd_dflt_accept(void *vc, void **vcpp)
{
	vcd_dflt_ctx_t *ctx1;
	vcd_dflt_ctx_t *ctx2;
	struct sockaddr_storage sa;
	socklen_t len;
	int flags;
	int fd;
	int ret;

	if (!vc || !vcpp) {
		return EINVAL;
	}

	ctx1 = (vcd_dflt_ctx_t *)vc;
	switch (ctx1->vdc_state) {
	case VCDD_STATE_LISTEN:
		break;
	case VCDD_STATE_ERROR:
		return ctx1->vdc_err;
	default:
		return EINVAL;
	}

	memset(&sa, 0, sizeof(sa));
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
	sa.ss_len = sizeof(sa);
#endif
	len = sizeof(sa);
	ret = accept(ctx1->vdc_fd, (struct sockaddr *)&sa, &len);
	if (ret < 0) {
		*vcpp = NULL;
		return errno;
	}

	fd = ret;

	/* switch it to non-blocking */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		ret = errno;
		close(fd);
		return ret;
	}
	flags |= O_NONBLOCK|O_NDELAY;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret != 0) {
		ret = errno;
		close(fd);
		return ret;
	}

	/* close on exec */
	ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (ret != 0) {
		ret = errno;
		close(fd);
		return ret;
	}

	ctx2 = (vcd_dflt_ctx_t *)malloc(sizeof(*ctx1));
	if (!ctx2) {
		close(fd);
		return ENOMEM;
	}

	memset(ctx2, 0, sizeof(*ctx2));
	ctx2->vdc_state = VCDD_STATE_ESTABLISHED;
	ctx2->vdc_fd = fd;

	*vcpp = ctx2;
	return 0;
}

static int
vcd_dflt_getladdr(void *vc, arpc_addr_t *nb)
{
	vcd_dflt_ctx_t *ctx;
	struct sockaddr_storage ss;
	socklen_t slen;
	int err;
	
	if (!vc || !nb) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;

	memset(&ss, 0, sizeof(ss));
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
	ss.ss_len = sizeof(ss);
#endif
	slen = sizeof(ss);
	err = getsockname(ctx->vdc_fd, (struct sockaddr *)&ss, &slen);
	if (err < 0) {
		err = errno;
		return err;
	}

	nb->buf = malloc(slen);
	if (!nb->buf) {
		return ENOMEM;
	}
	memcpy(nb->buf, &ss, slen);
	nb->len = slen;
	nb->maxlen = slen;
	return 0;
}

static int
vcd_dflt_getfamily(void *vc, sa_family_t *famp)
{
	vcd_dflt_ctx_t *ctx;
	struct sockaddr_storage ss;
	socklen_t slen;
	int err;
	
	if (!vc || !famp) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;

	memset(&ss, 0, sizeof(ss));
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
	ss.ss_len = sizeof(ss);
#endif
	slen = sizeof(ss);
	err = getsockname(ctx->vdc_fd, (struct sockaddr *)&ss, &slen);
	if (err < 0) {
		err = errno;
		return err;
	}
	*famp = ss.ss_family;
	return 0;
}

static int
vcd_dflt_islistener(void *vc, bool_t *listenp)
{
	vcd_dflt_ctx_t *ctx;
	
	if (!vc || !listenp) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;

	if (ctx->vdc_state == VCDD_STATE_LISTEN) {
		*listenp = TRUE;
	} else {
		*listenp = FALSE;
	}
	return 0;
}

static int
vcd_dflt_listen(void *vc, const arpc_addr_t *addr)
{
	vcd_dflt_ctx_t *ctx;
	struct sockaddr *sa;
	mode_t oldmask;
	int flags;
	int err;
	int fd;
	
	if (!vc || !addr) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vc;

	if (ctx->vdc_fd >= 0 || ctx->vdc_state != VCDD_STATE_CLOSED) {
		return EBUSY;
	}

	if (addr->len < sizeof(*sa)) {
		return EINVAL;
	}
	sa = (struct sockaddr *)addr->buf;
	switch (sa->sa_family) {
	case AF_INET:
		if (addr->len < sizeof(struct sockaddr_in)) {
			return EINVAL;
		}
		break;
	case AF_INET6:
		if (addr->len < sizeof(struct sockaddr_in6)) {
			return EINVAL;
		}
		break;
	case AF_LOCAL:
		if (addr->len < sizeof(struct sockaddr_un)) {
			return EINVAL;
		}
		break;
	default:
		return EINVAL;
	}

	fd = socket(sa->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		return errno;
	}

	/* nonblock */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		err = errno;
		close(fd);
		return err;
	}
	flags |= O_NONBLOCK|O_NDELAY;
	err = fcntl(fd, F_SETFL, flags);
	if (err != 0) {
		err = errno;
		close(fd);
		return err;
	}

	/* close on exec */
	err = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (err != 0) {
		err = errno;
		close(fd);
		return err;
	}

	/* ensure all execute mode flags are set for unix domain sockets */
	oldmask = umask(S_IXUSR|S_IXGRP|S_IXOTH);
	err = bind(fd, (struct sockaddr *)addr->buf, addr->len);
	umask(oldmask);
	if (err != 0) {
		err = errno;
		close(fd);
		return err;
	}

	err = listen(fd, 5);
	if (err != 0) {
		err = errno;
		close(fd);
		return err;
	}
	ctx->vdc_fd = fd;
	ctx->vdc_state = VCDD_STATE_LISTEN;

	return 0;
}


static int
vcd_dflt_init(ar_clnt_attr_t *attr, ar_svc_attr_t *svc_attr, void **vcpp)
{
	vcd_dflt_ctx_t *ctx;

	if (!vcpp) {
		return EINVAL;
	}

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		return ENOMEM;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->vdc_state = VCDD_STATE_CLOSED;
	ctx->vdc_fd = -1;
	ctx->vdc_bufcnt = 0;
	ctx->vdc_events = 0;
	*vcpp = ctx;
	return 0;
}

static int
vcd_dflt_destroy(void *vcp)
{
	vcd_dflt_ctx_t *ctx;
	
	if (!vcp) {
		return EINVAL;
	}

	ctx = (vcd_dflt_ctx_t *)vcp;

	if (ctx->vdc_fd >= 0) {
		close(ctx->vdc_fd);
		ctx->vdc_fd = -1;
	}

	free(ctx);
	return 0;
}

int
ar_vcd_lookup(ar_ioctx_t ioctx, const char *protoid, ar_vcd_t *drv)
{
	driver_map_t   drv_map;

	if (!ioctx || !drv) {
		return EINVAL;
	}

	if (!TAILQ_EMPTY(&ioctx->icx_drv_list)) {
		TAILQ_FOREACH(drv_map, &ioctx->icx_drv_list, drv_listent) {
			if (!strcmp(drv_map->drv_proto, protoid)) {
				*drv = drv_map->drv_vcd;
				return EOK;
			}
		}	
	}
	*drv = &vcd_default;
	return EOK;
}


int
ar_vcd_default(ar_vcd_t *drv)
{
	if (!drv) {
		return EINVAL;
	}

	*drv = &vcd_default;
	return 0;
}

int
ar_vcd_listen(ar_vcd_t drv, const arpc_addr_t *addr,
	      void **streampp)
{
	void *stream;
	int err;

	if (!drv || !addr || !streampp || !addr->buf) {
		return EINVAL;
	}
	
	err = (*drv->vcd_init)(NULL, NULL, &stream);
	if (err != 0) {
		return err;
	}

	err = (*drv->vcd_listen)(stream, addr);
	if (err != 0) {
		(*drv->vcd_destroy)(stream);
		return err;
	}

	*streampp = stream;
	return 0;
}


int
ar_vcd_fromfd(ar_svc_attr_t *attr, ar_vcd_t drv, int fd, void **streampp)
{
	if (!drv || !streampp || fd < 0) {
		return EINVAL;
	}
	
	if (!drv->vcd_from_fd) {
		return EINVAL;
	}

	return (*drv->vcd_from_fd)(attr, fd, streampp);
}

void
ar_vcd_close(ar_vcd_t drv, void *stream)
{
	if (!drv) {
		return;
	}

	(*drv->vcd_destroy)(stream);
}

static int
io_vcd_read(void *arg, void *buf, size_t *lenp)
{
	ar_ioep_t	ioep;
	vc_ioep_t	*vep;
	ar_vcd_t	vcd;
	struct iovec	vec[1];
	int		err;

	if (!arg || !buf || !lenp) {
		return AXDR_ERROR;
	}

	ioep = (ar_ioep_t)arg;
	vep = (vc_ioep_t *)ioep->iep_drv_arg;
	vcd = vep->vep_vcd;

	vec[0].iov_base = buf;
	vec[0].iov_len = *lenp;

	err = (*vcd->vcd_read)(vep->vep_stream, vec, 1, lenp);
	if (err != 0 && err != EAGAIN) {
		vep->vep_flags &= ~VEP_FLG_CLEANSHUTDOWN;
		vc_syserror(vep, err);
		return err;
	}
	if (err == 0 && *lenp == 0) {
		/* We can't dispatch disconnect from here. We need to
		 * let it push up through the rest of the rx path if 
		 * there is any buffere rx data.  The cleanshutdown flag
		 * let's us know if it's safe to do a clean disconnect here.
		 */
		vep->vep_flags |= VEP_FLG_DISCONNECTED;
		if (vep->vep_flags & VEP_FLG_CLEANSHUTDOWN) {
			/* we are at a point where no more data is fine.
			 * do the shutdown inline.
			 */
			vc_dispatch_disconnect(ioep, ARPC_SUCCESS);
			vc_syserror(vep, ENOTCONN);
			/* eagain causes us to pop up the stack without
			 * a bunch of errors occuring.
			 */
			return EAGAIN;
		}
	} else {
		vep->vep_flags &= ~VEP_FLG_CLEANSHUTDOWN;
	}

	return err;
}

static int
io_vcd_write(void *arg, void *buf, size_t *lenp)
{
	ar_ioep_t	ioep;
	vc_ioep_t	*vep;
	ar_vcd_t	vcd;
	struct iovec	vec[1];
	int		err;

	if (!arg || !buf || !lenp) {
		return EINVAL;
	}

	ioep = (ar_ioep_t)arg;
	vep = (vc_ioep_t *)ioep->iep_drv_arg;
	vcd = vep->vep_vcd;

	vec[0].iov_base = buf;
	vec[0].iov_len = *lenp;

	err = (*vcd->vcd_write)(vep->vep_stream, vec, 1, lenp);
	if (err != 0 && err != EAGAIN) {
		vc_syserror(vep, err);
		return err;
	}

	return err;
}

static int
io_vcd_ep_create(ar_ioctx_t ctx, ar_vcd_t drv, void *drv_arg, 
		 int sendsz, int recvsz, bool_t have_drv_arg, 
		 vep_type_t type, ar_clnt_attr_t *attr, 
		 ar_svc_attr_t *sattr, arpc_err_t *errp, ar_ioep_t *ioepp)
{
	vc_ioep_t  *vep;
	ar_ioep_t ioep;
	struct timespec ts;
	const char *prefix;
	ar_stat_t status;
	FILE *fp;
	int err;
	int len;

	if (!ioepp || !drv) {
		status = ARPC_ERRNO;
		err = EINVAL;
		goto error;
	}

	switch (type) {
	case VEP_TYPE_LISTENER:
		if (!sattr) {
			status = ARPC_ERRNO;
			err = EINVAL;
			goto error;
		}
		break;
	case VEP_TYPE_CONNECTION:
		break;
	default:
		status = ARPC_ERRNO;
		err = EINVAL;
		goto error;
	}

	len = sizeof(*ioep) + sizeof(*vep);
	ioep = malloc(len);
	if (!ioep) {
		status = ARPC_ERRNO;
		err = ENOMEM;
		goto error;
	}
	memset(ioep, 0, len);
	vep = (vc_ioep_t *)&ioep[1];

	if (attr) {
		fp = attr->ca_debug_file;
		prefix = attr->ca_debug_prefix;
	} else if (sattr) {
		fp = sattr->sa_debug_file;
		prefix = sattr->sa_debug_prefix;
	} else {
		fp = NULL;
		prefix = NULL;
	}

	ar_gettime(&ts);
	if (type == VEP_TYPE_CONNECTION && attr) {
		tspecadd(&ts, &attr->ca_create_tmout, &vep->vep_estb_limit);
	} else if (sattr && tspecisset(&sattr->sa_create_tmout)) {
		tspecadd(&ts, &sattr->sa_create_tmout, &vep->vep_estb_limit);
	} else {
		struct timespec tmpts;
		tmpts.tv_sec = CG_DEF_CONN_TIMEOUT_SECS;
		tmpts.tv_nsec = CG_DEF_CONN_TIMEOUT_NSECS;
		tspecadd(&ts, &tmpts, &vep->vep_estb_limit);
	}

	err = ar_ioep_init(ioep, ctx, IOEP_TYPE_VC, &vc_ep_driver, vep,
			    fp, prefix);
	if (err != 0) {
		free(ioep);
		status = ARPC_ERRNO;
		goto error;
	}

	err = axdrrec_create(&vep->vep_xdrs, sendsz, recvsz, ioep, 
			    &io_vcd_read, &io_vcd_write);
	if (err != 0) {
		ar_ioep_cleanup(ioep);
		free(ioep);
		status = ARPC_ERRNO;
		goto error;
	}

	vep->vep_vcd = drv;
	if (have_drv_arg) {
		vep->vep_stream = drv_arg;
	} else {
		err = drv->vcd_init(attr, sattr, &vep->vep_stream);
		if (err != 0) {
			axdr_destroy(&vep->vep_xdrs);
			ar_ioep_cleanup(ioep);
			free(ioep);
			status = ARPC_ERRNO;
			goto error;
		}
	}

	vep_init_async(&vep->vep_async_rx);
	vep_init_async(&vep->vep_async_tx);
	
	ar_gettime(&vep->vep_svc_last_rx);

	vep->vep_ioep = ioep;
	vep->vep_rx_state = VEP_RX_STATE_SKIPRECORD;

	vep->vep_tx_state = VEP_TX_STATE_IDLE;
	TAILQ_INIT(&vep->vep_tx_list);

	vep->vep_flowctl_lo_bytes = 32 * 1024;
	vep->vep_flowctl_hi_bytes = 64 * 1024;
	vep->vep_flowctl_max_bytes = 96 * 1024;
	vep->vep_tx_hi_prio_guaranteed = 5;
	vep->vep_type = type;
	vep->vep_sys_error = -1;
	vep->vep_sendsz = sendsz;
	vep->vep_recvsz = recvsz;
	if (sattr) {
		vep->vep_max_connections = sattr->sa_max_connections;
		vep->vep_accept_cb = sattr->sa_accept_cb;
		vep->vep_accept_arg = sattr->sa_accept_arg;
	} else {
		vep->vep_max_connections = 20;
	}

	*ioepp = ioep;
	RPCTRACE(ctx, 3, "io_vcd_ep_create(): %p\n", ioep);
	
	return 0;

error:
	if (errp) {
		errp->re_status = status;
		if (status == ARPC_ERRNO) {
			errp->re_errno = err;
		}
	}
	return err;
}

static void
io_vcd_ep_destroy(ar_ioep_t ioep)
{
	vc_ioep_t *vep;

	if (!ioep) {
		return;
	}

	vep = (vc_ioep_t *)ioep->iep_drv_arg;

	ar_ioep_cleanup(ioep);
	
	axdr_destroy(&vep->vep_xdrs);

	if (vep->vep_raddr.buf) {
		free(vep->vep_raddr.buf);
		vep->vep_raddr.buf = NULL;
	}
	
	if (vep->vep_stream) {
		(*vep->vep_vcd->vcd_destroy)(vep->vep_stream);
		vep->vep_stream = NULL;
		vep->vep_vcd = NULL;
	}

	astk_cleanup(&vep->vep_async_rx.as_stack);
	astk_cleanup(&vep->vep_async_tx.as_stack);

	axdr_free((axdrproc_t)&axdr_msg, &vep->vep_rx_msg);

	free(ioep);
}

static void
vc_call_sent(void *arg, int err)
{
	ar_clnt_call_obj_t cco;
	arpc_err_t result;
	ar_stat_t status;

	cco = (ar_clnt_call_obj_t)arg;
	assert(cco != NULL);
#if 0
	if (cco->cco_state != CCO_STATE_PENDING) {
        	printf("Invalid cco = %p cco_state =%d\n", cco, cco->cco_state);
        	return;
    	}
#endif
	assert(cco->cco_state == CCO_STATE_PENDING);

	cco->cco_state = CCO_STATE_RUNNING;

	/* if the call has no result handler, then it is assumed async,
	 * and we don't wait for a reply.  This is similar to behavior
	 * in the original sun rpc library.
	 */
	if (!cco->cco_xres && err == 0) {
		vc_cco_bumpref(cco);

		if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
			cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
			/* have to drop the user's reference.  Notify let's
			 * them know what happened.
			 */
			vc_cco_dropref(cco);
			cco->cco_rpc_err.re_status = ARPC_SUCCESS;
			result = cco->cco_rpc_err;
			(*cco->cco_cb)(cco, cco->cco_cb_arg, &result, NULL);
		}
		vc_cco_destroy(cco);
		vc_cco_dropref(cco);
		return;
	}

	/* XXX Do we want to free the input args here if it's a buffer? */
	if (err == 0) {
		return;
	}

	if (err == EPARSE) {
		status = ARPC_CANTENCODEARGS;
	} else {
		status = ARPC_CANTSEND;
	}

	vc_cco_bumpref(cco);

	if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
		cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
		/* have to drop the user's reference.  Notify let's
		 * them know what happened.
		 */
		vc_cco_dropref(cco);
		cco->cco_rpc_err.re_status = status;
		result = cco->cco_rpc_err;
		(*cco->cco_cb)(cco, cco->cco_cb_arg, &result, NULL);
	}
	vc_cco_destroy(cco);
	vc_cco_dropref(cco);
}

static void
vc_ref_all_clients(ar_ioep_t ep)
{
	vc_ioep_t *vep;
	ar_client_t *cl;

	vep = (vc_ioep_t *)ep->iep_drv_arg;

	vep->vep_iref_val++;

	vc_ioep_bumpref(ep);

	/* add a reference to everything first */
	TAILQ_FOREACH(cl, &ep->iep_client_list, cl_listent) {
		vc_clnt_bumpref(cl);
	}
}

static void
vc_unref_all_clients(ar_ioep_t ep)
{
	vc_ioep_t *vep;
	ar_client_t *clnext;
	ar_client_t *cl;

	vep = (vc_ioep_t *)ep->iep_drv_arg;

	vep->vep_iref_val--;

	for (cl = TAILQ_FIRST(&ep->iep_client_list); cl; cl = clnext) {
		clnext = TAILQ_NEXT(cl, cl_listent);
		vc_clnt_dropref(cl);
	}

	vc_ioep_dropref(ep);
}

static void
vc_dispatch_disconnect(ar_ioep_t ep, ar_stat_t err)
{
	ar_client_t	*cl;
	ar_client_t	*clnext;
	arpc_err_t 	eval;

	vc_ref_all_clients(ep);

	/* do all the notifies */
	for (cl = TAILQ_FIRST(&ep->iep_client_list); cl; cl = clnext) {
		clnext = TAILQ_NEXT(cl, cl_listent);
		if ((cl->cl_flags & CLNT_FLG_DISCON_CALLED) == 0 &&
		    (cl->cl_flags & CLNT_FLG_USRREF_DEC) == 0 &&
		    cl->cl_discon_cb) {
			cl->cl_flags |= CLNT_FLG_DISCON_CALLED;
			eval.re_status = err;
			(*cl->cl_discon_cb)(cl, cl->cl_discon_cb_arg, &eval);
		}
	}

	vc_unref_all_clients(ep);
}

static void
vc_dispatch_connected(ar_ioep_t ep, ar_stat_t err)
{
	ar_client_t	*cl;
	ar_client_t	*clnext;
	arpc_createerr_t cerr;

	vc_ref_all_clients(ep);

	cerr.cf_stat = err;

	/* do all the notifies.  Have to keep track of next because
	 * a handoff can remove the client from the list in conn_cb.
	 */
	for (cl = TAILQ_FIRST(&ep->iep_client_list); cl; cl = clnext) {
		clnext = TAILQ_NEXT(cl, cl_listent);
		if ((cl->cl_flags & CLNT_FLG_USRREF_DEC) == 0 && 
		    cl->cl_conn_cb) {
			(*cl->cl_conn_cb)(cl, cl->cl_conn_cb_arg, &cerr);
		}
	}

	vc_unref_all_clients(ep);
}

static int
vc_add_svc_ctx(ar_ioep_t ioep, ar_svc_attr_t *attr)
{
	ar_svc_xprt_t		*xp;

	if (!ioep || ioep->iep_svc_ctx) {
		/* something not right */
		return EINVAL;
	}

	xp = malloc(sizeof(*xp));
	if (!xp) {
		return ENOMEM;
	}
	memset(xp, 0, sizeof(*xp));

	xp->xp_refcnt = 1;	/* user reference */
	xp->xp_flags = 0;
	xp->xp_ops = &vc_xp_ops;
	xp->xp_ioep = ioep;
	xp->xp_ioctx = ioep->iep_ioctx;
	xp->xp_queued_err = -1;

	if (attr) {
		xp->xp_error_cb = attr->sa_error_cb;
		xp->xp_error_arg = attr->sa_error_arg;
	}

	/* add xp to ioep */
	ioep->iep_svc_ctx = xp;
	ioep->iep_flags |= IEP_FLG_ALLOW_SVC;	/* allow serving */

	return 0;
}


int
ar_clnt_vc_create(ar_ioctx_t ctx, ar_vcd_t drv, const arpc_addr_t *svcaddr,
		  const arpcprog_t prog, const arpcvers_t ver, 
		  ar_clnt_attr_t *attr, arpc_createerr_t *errp, 
		  ar_client_t **retp)
{
	ar_clnt_attr_t		lattr;
	vc_ioep_t		*vep;
	ar_ioep_t		ioep;
	int			sendsz;
	int			recvsz;
	struct sockaddr		*sa;
	ar_client_t		*cl;
	int			err;
	bool_t			conn;
	ar_clnt_call_obj_t	cco;
	struct timespec		cur;
	arpc_err_t		aerr;
	ar_stat_t		status;

	status = ARPC_SUCCESS;
	memset(&aerr, 0, sizeof(aerr));
	if (!ctx || !svcaddr || !retp || !svcaddr->buf) {
		status = ARPC_ERRNO;
		err = EINVAL;
		goto error;
	}

	if (!drv) {
		drv = &vcd_default;
	}

	if (!attr) {
		err = ar_clnt_attr_init(&lattr);
		if (err != 0) {
			status = ARPC_ERRNO;
			goto error;
		}
		attr = &lattr;
	}

	sa = (struct sockaddr *)svcaddr->buf;

	sendsz = ar_get_t_size(sa->sa_family, 
			       IPPROTO_TCP, attr->ca_sendsz);
	recvsz = ar_get_t_size(sa->sa_family, 
			       IPPROTO_TCP, attr->ca_recvsz);

	/* create the ioep */
	err = io_vcd_ep_create(ctx, drv, NULL, sendsz, recvsz, FALSE, 
			       VEP_TYPE_CONNECTION, attr, NULL, &aerr, &ioep);
	if (err != 0) {
		if (errp) {
			errp->cf_error = aerr;
			errp->cf_stat = aerr.re_status;
		}
		/* null out errp, don't want to override lower level error */
		errp = NULL;
		goto error;
	}

	/* get the connection started */
	vep = (vc_ioep_t *)ioep->iep_drv_arg;

	/* create the client */
	cl = malloc(sizeof(*cl));
	if (!cl) {
		io_vcd_ep_destroy(ioep);
		status = ARPC_ERRNO;
		err = ENOMEM;
		goto error;
	}
	memset(cl, 0, sizeof(*cl));

	cl->cl_refcnt = vep->vep_iref_val + 1;
	cl->cl_ops = &vc_clnt_ops;
	cl->cl_ioep = ioep;
	cl->cl_ioctx = ctx;
	cl->cl_prog = prog;
	cl->cl_ver = ver;
	cl->cl_private = vep;
	cl->cl_defwait.tv_sec = CG_DEF_RPC_TIMEOUT_SECS;
	cl->cl_defwait.tv_nsec = CG_DEF_RPC_TIMEOUT_NSECS;
	cl->cl_queued_err = -1;

	if (attr && (attr->ca_flags & CA_FLG_REQUIRED) != 0) {
		cl->cl_flags |= CLNT_FLG_KILL_SVC;
	}

	/* FIXME: we need a per client private structure.  These should
	 * be in there...
	 */
	cl->cl_conn_cb = attr->ca_conn_cb;
	cl->cl_conn_cb_arg = attr->ca_conn_arg;
	cl->cl_discon_cb = attr->ca_discon_cb;
	cl->cl_discon_cb_arg = attr->ca_discon_arg;

	err = (*vep->vep_vcd->vcd_connect)(vep->vep_stream, svcaddr, errp);
	RPCTRACE(ioep->iep_ioctx, 3, "vcd_connect(): ioep %p err %d\n", ioep, err);
	if (err != 0) {
		free(cl);
		io_vcd_ep_destroy(ioep);
		/* null out errp, don't want to override lower level error */
		errp = NULL;
		goto error;
	}

	vep->vep_raddr.buf = malloc(svcaddr->len);
	if (!vep->vep_raddr.buf) {
		free(cl);
		io_vcd_ep_destroy(ioep);
		status = ARPC_ERRNO;
		err = ENOMEM;
		goto error;
	}
	memcpy(vep->vep_raddr.buf, svcaddr->buf, svcaddr->len);
	vep->vep_raddr.len = svcaddr->len;
	vep->vep_raddr.maxlen = svcaddr->len;

	/* add client to ioep */
	TAILQ_INSERT_TAIL(&ioep->iep_client_list, cl, cl_listent);

	/* add ioep to ioctx */
	TAILQ_INSERT_TAIL(&ctx->icx_ep_list, ioep, iep_listent);
	RPCTRACE(ioep->iep_ioctx, 3, "ar_clnt_vc_create(): ioep %p\n", ioep);

	if ((attr->ca_flags & CA_FLG_ALLOW_SVC) != 0) {
		err = vc_add_svc_ctx(ioep, NULL);
		if (err != 0) {
			ar_clnt_destroy(cl);
			status = ARPC_ERRNO;
			goto error;
		}
		/* no user reference returned, release reference */
		ioep->iep_svc_ctx->xp_refcnt--;
		ioep->iep_svc_ctx->xp_flags |= XP_FLG_USRREF_DEC;
		/* apply user context specified in attributes */
		ioep->iep_svc_ctx->xp_user = attr->ca_svc_user;
	}

	/* return client */
	*retp = cl;

	vc_ioep_bumpref(ioep);

	/* check to see if we're already connected */
	if ((vep->vep_flags & VEP_FLG_CONNECTED) == 0) {
		err = (*drv->vcd_control)(vep->vep_stream, AR_CLGET_CONNECTED,
					  &conn);
		if (err == 0 && conn) {
			vep->vep_flags |= VEP_FLG_CONNECTED;
			vc_dispatch_connected(ioep, ARPC_SUCCESS);

			if ((ioep->iep_flags & IEP_FLG_DESTROY) == 0) {
				ar_gettime(&cur);
				TAILQ_FOREACH(cco, &ioep->iep_clnt_calls,
					      cco_listent) {
					cco->cco_start = cur;
				}
				vep->vep_svc_last_rx = cur;
			}
		}
	}

	if ((ioep->iep_flags & IEP_FLG_DESTROY) != 0) {
		*retp = NULL;
		ar_clnt_destroy(cl);
		status = ARPC_INTR;
		err = EBUSY; 	/* don't know what error is correct */
	} else {
		err = 0;
	}

	vc_ioep_dropref(ioep);

 error:
	if (attr == &lattr) {
		ar_clnt_attr_destroy(&lattr);
	}
	if (errp) {
		errp->cf_stat = status;
		errp->cf_error.re_status = status;
		if (status == ARPC_ERRNO) {
			errp->cf_error.re_errno = err;
		}
	}
	return err;
}

static int
clnt_vc_call(ar_client_t *cl, arpcproc_t proc, axdrproc_t xargs,
	     void *argsp, bool_t inplace, axdrproc_t xres,
	     void *resp, int ressize, ar_clnt_async_cb_t cb,
	     void *cb_arg, struct timespec *tout,
	     ar_clnt_call_obj_t *ccop)
{
	ar_clnt_call_obj_t	cco;
	vep_tx_obj_t	*txo;
	vc_ioep_t	*vep;
	ar_ioep_t	ioep;
	int		len;
	int		size;
	int		err;

	if (!cl || !xargs || !cb || !ccop) {
		return EINVAL;
	}

	ioep = cl->cl_ioep;
	vep = (vc_ioep_t *)cl->cl_private;

	if (cl->cl_queued_err > 0) {
		return cl->cl_queued_err;
	}

	if (!ioep || !vep) {
		return ENOTCONN;
	}

	if (vep->vep_sys_error > 0) {
		return vep->vep_sys_error;
	}

	len = sizeof(*cco) + sizeof(vep_tx_obj_t);
	cco = malloc(len);
	if (!cco) {
		return ENOMEM;
	}
	memset(cco, 0, len);
	err = ar_clnt_cco_init(cco, cl, ioep->iep_auth, &ioep->iep_xid_state,
			       proc, xargs, argsp, inplace, xres, 
			       resp, ressize, cb, cb_arg, tout);
	if (err != 0) {
		free(cco);
		return err;
	}

	txo = (vep_tx_obj_t *)&cco[1];
	size = axdr_sizeof((axdrproc_t)axdr_msg, &cco->cco_call);

	txo->to_msgtype = VEP_MSGTYPE_CALL;
	txo->to_flags = TO_FLG_SINGLE_BUF;
	txo->to_size = size;

	switch (cco->cco_rtype) {
	case CLNT_ARGS_TYPE_XDR:
		txo->to_type = VEP_TX_TYPE_XDR;
		txo->to_data.to_xdr.obj = &cco->cco_call;
		txo->to_data.to_xdr.xdrp = (axdrproc_t)axdr_msg;
		break;
	case CLNT_ARGS_TYPE_BUF:
		txo->to_type = VEP_TX_TYPE_BUF;
		txo->to_data.to_buffer.buf = cco->cco_args.cco_buffer.buf;
		txo->to_data.to_buffer.len = cco->cco_args.cco_buffer.len;
		break;
	default:
		free(cco);
		return EINVAL;
	}

	txo->to_opaque = cco;
	txo->to_done = &vc_call_sent;

	cco->cco_lower = txo;

	/* bump client reference for ref from cco */
	vc_clnt_bumpref(cl);

	TAILQ_INSERT_TAIL(&ioep->iep_clnt_calls, cco, cco_listent);
	TAILQ_INSERT_TAIL(&vep->vep_tx_list, txo, to_listent);

	vc_update_flowctl(vep);

	*ccop = cco;

	if (ioep->iep_ioctx) {
		axdr_op_t op;
		astk_t *async;

		/* try to start sending the request early to reduce
		 * latency if we can.  Also, some code assumes for async
		 * requests there is a good chance the call msg has been
		 * send by the time this function returns.
		 *
		 * This feature (which allows instant completion of async,
		 * or no response, messages), adds significant complexity.
		 *
		 * Since the user can call this function directly, and many
		 * user callbacks happen from within vc_read/vc_write, we
		 * now have a recursive entry path for vc_write being called
		 * within user callbacks in both those routines.
		 */
		vc_ioep_bumpref(ioep);

		/* because there is a good chance we're called from vc_read
		 * (next call is started from previous completion callback),
		 * we have to flip our axdr state correctly.
		 * 
		 * We also have to be careful, because vc_write can
		 * be entered re-cursively from async (no result) calls since
		 * we complete those calls from vc_call_sent.
		 */
		async = vep->vep_xdrs.x_async;
		op = vep->vep_xdrs.x_op;

		vc_write(ioep->iep_ioctx, vep, ioep);

		vep->vep_xdrs.x_async = async;
		vep->vep_xdrs.x_op = op;

		vc_ioep_dropref(ioep);
	}

	return 0;
}

static int
clnt_vc_cancel(ar_client_t *cl, ar_clnt_call_obj_t cco)
{
	if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
		cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
		vc_cco_destroy(cco);
		vc_cco_dropref(cco);
	} else {
		vc_cco_destroy(cco);
	}
	return 0;
}

static void
clnt_vc_reauth(ar_client_t *cl, ar_clnt_call_obj_t cco)
{
	ar_stat_t	cerr;
	vc_ioep_t	*vep;
	vep_tx_obj_t	*txo;
	ar_ioep_t	ioep;
	arpc_err_t	result;
	int		err;

	err = 0;

	if (!cl || !cco) {
		return;
	}

	vc_cco_bumpref(cco);

	txo = (vep_tx_obj_t *)cco->cco_lower;
	assert(txo != NULL);

	ioep = cl->cl_ioep;
	if (!ioep) {
		cerr = ARPC_CANTCONNECT;
		goto error;
	}
	vep = (vc_ioep_t *)ioep->iep_drv_arg;
	assert(vep != NULL);

	if ((cco->cco_flags & CCO_FLG_DESTROY) != 0 ||
	    cco->cco_state != CCO_STATE_RESULTS) {
		cerr = ARPC_INTR;
		goto error;
	}		

	err = ar_clnt_cco_reauth(ioep->iep_auth, cco);
	if (err != 0) {
		cerr = ARPC_ERRNO;
		goto error;
	}

	/* need to queue up to re-xmit msg with updated auth info */
	cco->cco_state = CCO_STATE_PENDING;
	TAILQ_INSERT_TAIL(&vep->vep_tx_list, txo, to_listent);
	vc_update_flowctl(vep);

	vc_cco_dropref(cco);
	return;


 error:
	if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
		cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
		cco->cco_rpc_err.re_status = cerr;
		if (cerr == ARPC_ERRNO) {
			cco->cco_rpc_err.re_errno = err;
		}
		result = cco->cco_rpc_err;
		(*cco->cco_cb)(cco, cco->cco_cb_arg, &result, NULL);
		vc_cco_dropref(cco);
	}
	vc_cco_destroy(cco);
	vc_cco_dropref(cco);
	return;
}


static void
clnt_vc_destroy(ar_client_t *cl)
{
	if (!cl) {
		return;
	}

	vc_clnt_bumpref(cl);

	if ((cl->cl_flags & CLNT_FLG_USRREF_DEC) == 0) {
		cl->cl_flags |= CLNT_FLG_USRREF_DEC;
		vc_clnt_dropref(cl);
	}

	vc_clnt_destroy(cl);
	vc_clnt_dropref(cl);
}


static bool_t
clnt_vc_control(ar_client_t *cl, u_int request, void *info)
{
	struct timespec ts;
	int fd;
	socklen_t optlen;
	ar_ioep_t ioep;
	vc_ioep_t *vep;
	ar_vcd_t vcd;
	int err;

	if (!cl) {
		return FALSE;
	}

	if (cl->cl_queued_err > 0) {
		return cl->cl_queued_err;
	}

	ioep = cl->cl_ioep;
	if (!ioep) {
		return FALSE;
	}
	vep = (vc_ioep_t *)ioep->iep_drv_arg;
	assert(vep != NULL);
	vcd = vep->vep_vcd;

	/* for other requests which use info */
	if (info == NULL) {
		return FALSE;
	}

	if (vep->vep_sys_error > 0) {
		return FALSE;
	}

	switch (request) {
	case AR_CLSET_TIMEOUT:
		ts.tv_sec = ((struct timeval *)info)->tv_sec;
		ts.tv_nsec = ((struct timeval *)info)->tv_usec * 1000;

		if (ar_time_not_ok(&ts)) {
			return (FALSE);
		}
		cl->cl_defwait = ts;
		break;
	case AR_CLGET_TIMEOUT:
		((struct timeval *)info)->tv_sec = cl->cl_defwait.tv_sec;
		((struct timeval *)info)->tv_usec = 
			cl->cl_defwait.tv_nsec / 1000;
		break;
	case AR_CLGET_SERVER_ADDR:
		err = (*vcd->vcd_control)(vep->vep_stream,
					   AR_CLGET_SERVER_ADDR, info);
		return err == 0 ? TRUE : FALSE;
	case AR_CLGET_FD:
		err = (*vep->vep_vcd->vcd_get_fd)(vep->vep_stream, 
						  (int *)info);
		if (err != 0) {
			return FALSE;
		}
		break;
	case AR_CLGET_PEERCRED:
#ifndef HAVE_SO_PEERCRED
		return FALSE;
#else
		err = (*vep->vep_vcd->vcd_get_fd)(vep->vep_stream, &fd);
		if (err != 0) {
			return FALSE;
		}
		optlen = sizeof(struct ucred); 
		err = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, 
				 (struct ucred *)info, &optlen);
		if (err != 0) {
			return FALSE;
		}
#endif
		break;
	case AR_CLGET_SVC_ADDR:
		/* The caller should not free this memory area */
		*(arpc_addr_t *)info = vep->vep_raddr;
		break;
	case AR_CLSET_SVC_ADDR:		/* set to new address */
		return (FALSE);
	case AR_CLGET_XID:
		/*
		 * This will get the xid of the PREVIOUS call
		 */
		*(u_int32_t *)info = ioep->iep_xid_state.nextxid - 1;
		break;
	case AR_CLSET_XID:
		/* This will set the xid of the NEXT call */
		ioep->iep_xid_state.nextxid = *(u_int32_t *)info;
		break;
	case AR_CLGET_VERS:
		*(u_int32_t *)info = cl->cl_ver;
		break;

	case AR_CLSET_VERS:
		cl->cl_ver = *(u_int32_t *)info;
		break;

	case AR_CLGET_PROG:
		*(u_int32_t *)info = cl->cl_prog;
		break;

	case AR_CLSET_PROG:
		cl->cl_prog = *(u_int32_t *)info;
		break;
	case AR_CLGET_CONNECTED:
		*((bool_t *)info) = (vep->vep_flags & VEP_FLG_CONNECTED) ? 
			TRUE : FALSE;
		break;
	case AR_CLGET_LOCAL_ADDR:
		err = (*vcd->vcd_control)(vep->vep_stream,
					  AR_CLGET_LOCAL_ADDR, info);
		return err == 0 ? TRUE : FALSE;
	default:
		return ar_clnt_control_default(cl, request, info);
	}
	return TRUE;
}


static void
xp_vc_destroy(ar_svc_xprt_t *xp)
{
	if (!xp) {
		return;
	}

	vc_xp_bumpref(xp);

	if ((xp->xp_flags & XP_FLG_USRREF_DEC) == 0) {
		xp->xp_flags |= XP_FLG_USRREF_DEC;
		vc_xp_dropref(xp);
	}

	vc_xp_destroy(xp);
	vc_xp_dropref(xp);
}

static bool_t
xp_vc_control(ar_svc_xprt_t *xp, u_int cmd, void *info)
{
	ar_ioep_t ioep;
	ar_ioep_t ioep2;
	ar_vcd_t vcd;
	ar_svc_xprt_t *xp2;
	vc_ioep_t *vep;
	vc_ioep_t *vep2;
	int fd;
	int tmp;
	int err;
	socklen_t len;
	bool_t ret;

	if (!xp) {
		return FALSE;
	}

	ioep = xp->xp_ioep;
	if (!ioep) {
		return FALSE;
	}

	vep = (vc_ioep_t *)ioep->iep_drv_arg;
	if (!vep) {
		return FALSE;
	}

	vcd = vep->vep_vcd;

	switch (cmd) {
	case AR_SVCSET_DEBUG:
		if (info == NULL) {
			return FALSE;
		}
		ret = ar_svc_control_default(xp, cmd, info);
		if (!ret) {
			return FALSE;
		}
		if (vep->vep_type != VEP_TYPE_LISTENER ||
		    !ioep->iep_ioctx) {
			/* no need to update other streams */
			return TRUE;
		}

		TAILQ_FOREACH(ioep2, &ioep->iep_ioctx->icx_ep_list, 
			      iep_listent) {
			if (ioep2 == ioep ||
			    ioep2->iep_drv != &vc_ep_driver ||
			    TAILQ_FIRST(&ioep2->iep_client_list) != NULL) {
				continue;
			}
			xp2 = ioep2->iep_svc_ctx;
			vep2 = (vc_ioep_t *)ioep2->iep_drv_arg;
			if (!vep2 || !xp2) {
				continue;
			}
			if ((xp2->xp_flags & XP_FLG_USRREF_DEC) != 0) {
				/* user has a reference to this server link,
				 * they can manage debug themselves 
				 */
				continue;
			}

			ioep2->iep_debug_file = ioep->iep_debug_file;
		}
		return TRUE;
	case AR_SVCGET_FD:
		err = (*vep->vep_vcd->vcd_get_fd)(vep->vep_stream, &fd);
		if (err != 0) {
			return FALSE;
		}
		*((int *)info) = fd;
		return TRUE;
	case AR_SVCGET_REMOTE_ADDR:
		err = (*vcd->vcd_control)(vep->vep_stream,
					  AR_CLGET_SERVER_ADDR, info);
		return err == 0 ? TRUE : FALSE;
	case AR_SVCGET_LOCAL_ADDR:
		err = (*vcd->vcd_control)(vep->vep_stream,
					  AR_CLGET_LOCAL_ADDR, info);
		return err == 0 ? TRUE : FALSE;
	case AR_SVCGET_MAXCONNS:
		if (info == NULL) {
			return FALSE;
		}
		*((int *)info) = vep->vep_max_connections;
		return TRUE;
	case AR_SVCSET_MAXCONNS:
		if (info == NULL) {
			return FALSE;
		}
		tmp = (long)info;
		if (tmp < 1) {
			return FALSE;
		}
		vep->vep_max_connections = tmp;
		vc_update_flowctl(vep);
		return TRUE;
	case AR_SVCGET_PEERCRED:
#ifndef HAVE_SO_PEERCRED
		return FALSE;
#else
		err = (*vep->vep_vcd->vcd_get_fd)(vep->vep_stream, &fd);
		if (err != 0) {
			return FALSE;
		}
		len = sizeof(struct ucred);
		err = getsockopt(fd, SOL_SOCKET, SO_PEERCRED,
				 (struct ucred *)info, &len);
		if (err != 0) {
			return FALSE;
		}
#endif
		break;
	default:
		return ar_svc_control_default(xp, cmd, info);
	}
	return FALSE;
}


/**
 * Move all lower level state from src client to dst.
 *
 * This is used when the rpc bind client has made a vc client.  Once
 * the connection is established, it needs to associate the underlying
 * state for the successful connection (src) to the client structure
 * the user is using as a handle...
 *
 * @param src
 * @param dst
 * @param msglist
 * @param xstate
 * @param errp
 * @return
 */
static int
clnt_vc_handoff(ar_client_t *src, ar_client_t *dst, cco_list_t *msglist,
		struct ar_xid_state_s *xstate, 
		arpc_createerr_t *errp) 
{
	ar_ioep_t	ioep;
	ar_clnt_call_obj_t	cco;
	vep_tx_obj_t	*txo;
	vc_ioep_t	*vep;
	struct timespec	now;
	cco_list_t	list;
	int		err;

	if (!src || !dst || !msglist || !xstate) {
		return vc_syscreat_err(errp, EINVAL);
	}


	if (src->cl_ops != &vc_clnt_ops) {
		return vc_syscreat_err(errp, EINVAL);
	}

	ioep = src->cl_ioep;
	if (!ioep) {
		if (errp) {
			errp->cf_stat = ARPC_XPRTFAILED;
		}
		return ENOTCONN;
	}

	vep = (vc_ioep_t *)ioep->iep_drv_arg;
	assert(vep != NULL);

	ar_gettime(&now);

	TAILQ_INIT(&list);
	err = 0;

	while ((cco = TAILQ_FIRST(msglist)) != NULL) {
		if (cco->cco_state != CCO_STATE_QUEUED) {
			err = EINVAL;
			break;
		}

		/* have to allocate a seperate txo object to go along with
		 * this call request.
		 */
		txo = malloc(sizeof(*txo));
		if (!txo) {
			err = ENOMEM;
			break;
		}
		memset(txo, 0, sizeof(*txo));

		txo->to_msgtype = VEP_MSGTYPE_CALL;

		switch (cco->cco_rtype) {
		case CLNT_ARGS_TYPE_XDR:
			txo->to_type = VEP_TX_TYPE_XDR;
			txo->to_data.to_xdr.obj = cco->cco_args.cco_xdr.obj;
			txo->to_data.to_xdr.xdrp = cco->cco_args.cco_xdr.xdrp;
			txo->to_size = axdr_sizeof((axdrproc_t)axdr_msg, 
						  &cco->cco_call);
			break;
		case CLNT_ARGS_TYPE_BUF:
			txo->to_type = VEP_TX_TYPE_BUF;
			txo->to_data.to_buffer.buf = 
				cco->cco_args.cco_buffer.buf;
			txo->to_data.to_buffer.len = 
				cco->cco_args.cco_buffer.len;
			txo->to_size = cco->cco_args.cco_buffer.len;
			break;
		default:
			err = EINVAL;
			free(txo);
			txo = NULL;
			break;
		}
		if (!txo) {
			break;
		}

		txo->to_opaque = cco;
		txo->to_done = &vc_call_sent;

		/* Remove from the callers list */
		TAILQ_REMOVE(msglist, cco, cco_listent);

		cco->cco_lower = txo;
		TAILQ_INSERT_TAIL(&list, cco, cco_listent);
	}

	if (err != 0) {
		while ((cco = TAILQ_LAST(&list, cco_list_s)) != NULL) {
			TAILQ_REMOVE(&list, cco, cco_listent);

			txo = (vep_tx_obj_t *)cco->cco_lower;
			cco->cco_lower = NULL;
			free(txo);

			TAILQ_INSERT_HEAD(msglist, cco, cco_listent);
		}

		return vc_syscreat_err(errp, err);
	}

	/* move existing calls to new client.  Usually these don't
	 * exist, because the src client handle has not been exported
	 * out of the library.
	 */
	TAILQ_FOREACH(cco, &ioep->iep_clnt_calls, cco_listent) {
		if (cco->cco_client == src) {
			src->cl_refcnt--;
			cco->cco_client = dst;
			dst->cl_refcnt++;
		}
	}

	/* now that all the allocations that can fail are done, 
	 * make an atomic switch of all outstanding calls.
	 */
	while ((cco = TAILQ_FIRST(&list)) != NULL) {
		TAILQ_REMOVE(&list, cco, cco_listent);

		txo = (vep_tx_obj_t *)cco->cco_lower;

		/* associate call with ioep and tx object with the vep */
		TAILQ_INSERT_TAIL(&ioep->iep_clnt_calls, cco, cco_listent);
		TAILQ_INSERT_TAIL(&vep->vep_tx_list, txo, to_listent);

		/* bump dst reference for cco we're adding */
		vc_clnt_bumpref(dst);
		cco->cco_client = dst;
		cco->cco_state = CCO_STATE_PENDING;
		cco->cco_start = now;
	}

	vc_update_flowctl(vep);

	TAILQ_REMOVE(&ioep->iep_client_list, src, cl_listent);
	src->cl_refcnt -= vep->vep_iref_val;
	
	dst->cl_ops = &vc_clnt_ops;
	dst->cl_ioep = ioep;
	dst->cl_ioctx = src->cl_ioctx;
	dst->cl_private = vep;
	dst->cl_prog = src->cl_prog;
	dst->cl_ver = src->cl_ver;
	dst->cl_defwait = src->cl_defwait;
	dst->cl_discon_cb = src->cl_discon_cb;
	dst->cl_discon_cb_arg = src->cl_discon_cb_arg;

	/* add in all 'refall' style references */
	dst->cl_refcnt += vep->vep_iref_val;

	/* copy any important flags in the handoff */
	dst->cl_flags |= (src->cl_flags & CLNT_FLG_KILL_SVC);
		
	TAILQ_INSERT_TAIL(&ioep->iep_client_list, dst, cl_listent);

	/* move xid state over, so we maintain correct call # space */
	if (xstate) {
		ioep->iep_xid_state = *xstate;
	}

	src->cl_ioep = NULL;
	src->cl_ioctx = NULL;
	src->cl_private = NULL;

	/* get src into state that looks like destroy path */
	src->cl_queued_err = ESHUTDOWN;
	src->cl_flags |= CLNT_FLG_DESTROY;

	/* should be 1 remaining user reference.  This assert is just
	 * for the common library internal cases.  It should probably
	 * be removed. 
	 */
	assert(src->cl_refcnt == 1);

	/* our responsibility to release user reference, if it hasn't
	 * been already.
	 */
	if ((src->cl_flags & CLNT_FLG_USRREF_DEC) == 0) {
		src->cl_flags |= CLNT_FLG_USRREF_DEC;
		vc_clnt_dropref(src);
	}

	return 0;
}


static void
vc_reply_sent(void *arg, int err)
{
	ar_svc_call_obj_t sco;

	sco = (ar_svc_call_obj_t)arg;
	assert(sco != NULL);
	assert(sco->sco_state == SCO_STATE_SEND_REPLY);

	vc_sco_destroy(sco);
}


static int
xp_vc_sco_reply(ar_svc_xprt_t *xp, ar_svc_call_obj_t sco)
{
	vep_tx_obj_t	*txo;
	vc_ioep_t	*vep;
	ar_ioep_t	ioep;

	if (!xp || !sco) {
		return EINVAL;
	}

	ioep = xp->xp_ioep;
	if (!ioep) {
		return ENOTCONN;
	}

	vep = (vc_ioep_t *)ioep->iep_drv_arg;
	if (!vep) {
		return EINVAL;
	}

	/* need to queue up for xmit */
	if (sco->sco_state != SCO_STATE_CALL) {
		return EINVAL;
	}

	sco->sco_state = SCO_STATE_SEND_REPLY;
	txo = (vep_tx_obj_t *)sco->sco_lower;
	txo->to_type = VEP_TX_TYPE_XDR;
	txo->to_msgtype = VEP_MSGTYPE_SCO_REPLY;
	txo->to_data.to_xdr.xdrp = (axdrproc_t)&axdr_msg;
	txo->to_data.to_xdr.obj = &sco->sco_reply;
	txo->to_size = axdr_sizeof((axdrproc_t)&axdr_msg, &sco->sco_reply);
	txo->to_opaque = sco;
	txo->to_done = &vc_reply_sent;
			
	TAILQ_INSERT_TAIL(&vep->vep_tx_list, txo, to_listent);
	TAILQ_INSERT_TAIL(&ioep->iep_svc_replies, sco, sco_listent);

	vc_update_flowctl(vep);
	return 0;
}

static int
xp_vc_sco_alloc(ar_svc_xprt_t *xp, ar_svc_call_obj_t *scop)
{
	ar_svc_call_obj_t	sco;
	vep_tx_obj_t	*txo;
	int		len;
	int		err;

	if (!xp || !scop) {
		return EINVAL;
	}

	len = sizeof(*sco) + sizeof(*txo);
	sco = malloc(len);
	if (!sco) {
		return ENOMEM;
	}
	memset(sco, 0, len);

	txo = (vep_tx_obj_t *)&sco[1];
	err = ar_svc_sco_init(sco, xp);
	if (err != 0) {
		free(sco);
		return err;
	}

	sco->sco_lower = txo;

	/* bump xp ref so we don't loose our function handlers */
	vc_xp_bumpref(xp);

	*scop = sco;
	return 0;
}


static void
xp_vc_sco_destroy(ar_svc_xprt_t *xp, ar_svc_call_obj_t sco)
{
	if (!xp || !sco) {
		return;
	}

	vc_sco_bumpref(sco);

	if ((sco->sco_flags & SCO_FLG_USRREF_DEC) == 0) {
		sco->sco_flags |= SCO_FLG_USRREF_DEC;
		vc_sco_dropref(sco);
	}
	
	vc_sco_destroy(sco);
	vc_sco_dropref(sco);
}


int
ar_svc_vc_create(ar_ioctx_t ctx, ar_vcd_t drv, void *stream, 
		 ar_svc_attr_t *attr, arpc_err_t *errp, ar_svc_xprt_t **retp)
{
	ar_svc_attr_t	lattr;
	ar_ioep_t	ioep;
	vep_type_t	type;
	int		sendsz;
	int		recvsz;
	bool_t		listener;
	sa_family_t	family;
	ar_stat_t	status;
	int		err;

	status = ARPC_SUCCESS;

	if (!ctx || !drv || !stream || !retp) {
		status = ARPC_ERRNO;
		err = EINVAL;
		goto error;
	}

	err = (*drv->vcd_getfamily)(stream, &family);
	if (err != 0) {
		status = ARPC_ERRNO;
		goto error;
	}

	err = (*drv->vcd_islistener)(stream, &listener);
	if (err != 0) {
		status = ARPC_ERRNO;
		goto error;
	}

	if (listener) {
		type = VEP_TYPE_LISTENER;
	} else {
		type = VEP_TYPE_CONNECTION;
	}

	if (!attr) {
		err = ar_svc_attr_init(&lattr);
		if (err != 0) {
			status = ARPC_ERRNO;
			goto error;
		}
		attr = &lattr;
	}

	sendsz = ar_get_t_size(family, IPPROTO_TCP, attr->sa_sendsz);
	recvsz = ar_get_t_size(family, IPPROTO_TCP, attr->sa_recvsz);

	/* create the ioep */
	err = io_vcd_ep_create(ctx, drv, stream, sendsz, recvsz, TRUE,
			       type, NULL, attr, errp, &ioep);
	if (err != 0) {
		/* don't over-write lower-layer error */
		errp = NULL;
		goto error;
	}

	/* add ioep to ioctx */
	TAILQ_INSERT_TAIL(&ctx->icx_ep_list, ioep, iep_listent);

	/* create the ar_svc_xprt_t */
	err = vc_add_svc_ctx(ioep, attr);
	if (err != 0) {
		vc_ioep_destroy(ioep);
		status = ARPC_ERRNO;
		goto error;
	}

	/* return svc_ctx */
	*retp = ioep->iep_svc_ctx;
	err = 0;

 error:
	if (attr == &lattr) {
		ar_svc_attr_destroy(&lattr);
	}
	if (errp) {
		errp->re_status = status;
		if (status == ARPC_ERRNO) {
			errp->re_errno = err;
		}
	}
	return err;
}
