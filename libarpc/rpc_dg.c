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
 * rpc_dg.c
 *
 * common code for client/server dg (datagram/UDP) rpc links
 */

#include "compat.h"

#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_LIBEVENT
#include <event.h>
#endif

#include <libarpc/arpc.h>
#include "rpc_com.h"

typedef struct dge_call_s dge_call_t;
typedef struct dge_sco_s dge_sco_t;
typedef struct dg_ioep_s dg_ioep_t;

struct dge_call_s {
	int		dgc_flags;
	struct timespec	dgc_retran_interval;   /* interval */
	struct timespec	dgc_retran_limit;      /* absolute time */
	int		dgc_retran_count;
};

struct dge_sco_s {
	uint32_t	dgs_xid;
	struct timespec	dgs_cache_timeout;
	char		*dgs_cbuf;
	arpc_addr_t	dgs_addr;
	int		dgs_cbufsz;
};

#define DGC_FLG_SINGLE_BUF	0x00000001


/* NOTE: in the orignal sun code, this was 15 seconds.  I think this is 
 * more appropriate with current networks.
 */
#define DGE_BASE_RETRAN_SECS    2
#define DGE_BASE_RETRAN_NSECS   0

/*
 * This is the orignal max backoff value 
 */
#define	RPC_MAX_BACKOFF		30 /* seconds */

struct dg_ioep_s {
	uint32_t	dep_flags;
	arpc_addr_t	dep_raddr;	/* remote addr */
	ar_ioep_t	dep_ioep;
	struct timespec dep_rtran;	/* retransmit interval */
	bool_t		dep_connect;
	bool_t		dep_caching;
	int		dep_cache_bytes;
	struct timespec dep_cache_time;
	int		dep_fd;
	int		dep_gbl_cl_refcnt;
	char		*dep_buf;
	int		dep_bufsz;
	int		dep_sys_error;
	arpc_addr_t	*dep_cur_addr;
};

#define DEP_FLG_FLOWCTL  0x00000001

static void dg_setup(ar_ioep_t ep, struct pollfd *pfd, int *timeoutp);
static void dg_dispatch(ar_ioep_t ep, struct pollfd *pfd);
static void dg_destroy(ar_ioep_t ep);
static int dg_sendmsg(ar_ioep_t ep, arpc_msg_t *, ar_svc_call_obj_t);
static int dg_add_client(ar_ioep_t ep, const arpcprog_t, const arpcvers_t,
			 ar_clnt_attr_t *, arpc_err_t *errp,
			 ar_client_t **);
#ifdef HAVE_LIBEVENT
static int dg_event_setup(ar_ioep_t ep, struct event_base *evbase);
#endif

static int clnt_dg_call(ar_client_t *, arpcproc_t, axdrproc_t, void *, 
			bool_t inplace, axdrproc_t, void *, int, 
			ar_clnt_async_cb_t, void *, struct timespec *, 
			ar_clnt_call_obj_t *);
static void clnt_dg_destroy(ar_client_t *);
static bool_t clnt_dg_control(ar_client_t *, u_int, void *);
static int clnt_dg_handoff(ar_client_t *, ar_client_t *, cco_list_t *,
			   struct ar_xid_state_s *xstate,
			   arpc_createerr_t *errp);
static int clnt_dg_cancel(ar_client_t *, ar_clnt_call_obj_t cco);
static void clnt_dg_reauth(ar_client_t *, ar_clnt_call_obj_t cco);
static void clnt_dg_call_dropref(ar_client_t *, ar_clnt_call_obj_t cco);

static ep_driver_t dg_ep_driver = {
	dg_setup,
	dg_dispatch,
	dg_destroy,
	dg_sendmsg,
	dg_add_client,
#ifdef HAVE_LIBEVENT
	dg_event_setup
#endif
};

struct clnt_ops dg_clnt_ops = {
	clnt_dg_call, 
	clnt_dg_destroy,
	clnt_dg_control,
	clnt_dg_handoff,
	clnt_dg_cancel,
	clnt_dg_reauth,
	clnt_dg_call_dropref
};

static int xp_dg_sco_reply(ar_svc_xprt_t *xp, ar_svc_call_obj_t sco);
static int xp_dg_sco_alloc(ar_svc_xprt_t *xp, ar_svc_call_obj_t *scop);
static void xp_dg_sco_destroy(ar_svc_xprt_t *xp, ar_svc_call_obj_t sco);
static void xp_dg_destroy(ar_svc_xprt_t *xp);
static bool_t xp_dg_control(ar_svc_xprt_t *xp, const u_int cmd, void *info);

struct xp_ops dg_xp_ops = {
	xp_dg_sco_reply,
	xp_dg_sco_alloc,
	xp_dg_sco_destroy,
	xp_dg_destroy,
	xp_dg_control
};


static void dg_cco_destroy(ar_clnt_call_obj_t cco);
static void dg_ioep_destroy(ar_ioep_t ioep);
static void dg_clnt_bumpref(ar_client_t *cl);
static void dg_clnt_dropref(ar_client_t *cl);
static void dg_cco_bumpref(ar_clnt_call_obj_t cco);
static void dg_cco_dropref(ar_clnt_call_obj_t cco);
static void dg_sco_bumpref(ar_svc_call_obj_t sco);
static void dg_sco_dropref(ar_svc_call_obj_t sco);
static void dg_xp_bumpref(ar_svc_xprt_t *xp);
static void dg_xp_dropref(ar_svc_xprt_t *xp);
static void dg_ioep_bumpref(ar_ioep_t ioep);
static void dg_ioep_dropref(ar_ioep_t ioep);
static void io_dg_ep_destroy(ar_ioep_t ioep);


static void
dg_clnt_destroy(ar_client_t *cl)
{
	ar_clnt_call_obj_t	cco;
	ar_clnt_call_obj_t	cconext;
	ar_ioep_t		ioep;
	dg_ioep_t		*dep;
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
		dep = (dg_ioep_t *)ioep->iep_drv_arg;
		assert(dep != NULL);

		dg_ioep_bumpref(ioep);

		TAILQ_REMOVE(&ioep->iep_client_list, cl, cl_listent);
		cl->cl_refcnt -= dep->dep_gbl_cl_refcnt;
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
			if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
				/* steal back usr reference, after notify */
				cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
				(*cco->cco_cb)(cco, cco->cco_cb_arg,
					       &result, NULL);
				/* cco destroy expects ioep ptr to be
				 * valid.
				 */
				cl->cl_ioep = ioep;
				dg_cco_destroy(cco);
				cl->cl_ioep = NULL;
				/* actually drop usr ref */
				dg_cco_dropref(cco);	
			} else {
				/* can this happen? */
				cl->cl_ioep = ioep;
				dg_cco_destroy(cco);
				cl->cl_ioep = NULL;
			}
		}

		if ((cl->cl_flags & CLNT_FLG_DISCON_CALLED) == 0 && 
		    cl->cl_discon_cb != NULL) {
			cl->cl_flags |= CLNT_FLG_DISCON_CALLED;
			(*cl->cl_discon_cb)(cl, cl->cl_discon_cb_arg, &result);
		}

		/* release reference to ioep */
		if (TAILQ_FIRST(&ioep->iep_client_list) == NULL && 
		    ((cl->cl_flags & CLNT_FLG_KILL_SVC) != 0 ||
		     !ioep->iep_svc_ctx)) {
			/* we're the last client and there is no server
			 * context.  Destroy the connection.
			 */
			dg_ioep_destroy(ioep);
		}

		dg_ioep_dropref(ioep);
	}

	cl->cl_refcnt--;
	if (cl->cl_refcnt <= 0) {
		free(cl);
	}
}

static void
dg_cco_destroy(ar_clnt_call_obj_t cco)
{
	dge_call_t	*dgc;
	ar_client_t 		*cl;
	ar_ioep_t	ioep;
	dg_ioep_t	*dep;

	assert(cco != NULL);
	dgc = (dge_call_t *)cco->cco_lower;
	cl = cco->cco_client;
	assert(cl != NULL && dgc != NULL);
	if (cco->cco_state != CCO_STATE_DEAD) {
		ioep = cl->cl_ioep;
		assert(ioep != NULL);
		dep = (dg_ioep_t *)ioep->iep_drv_arg;
		assert(dep != NULL);
	} else {
		dep = NULL;
		ioep = NULL;
	}

	cco->cco_flags |= CCO_FLG_DESTROY;
		
	switch (cco->cco_state) {
	case CCO_STATE_QUEUED:
	case CCO_STATE_RESULTS:
	case CCO_STATE_DONE:
	case CCO_STATE_PENDING:
	case CCO_STATE_RUNNING:
		TAILQ_REMOVE(&ioep->iep_clnt_calls, cco, cco_listent);
		TAILQ_NEXT(cco, cco_listent) = NULL;
		ar_clnt_cco_cleanup(ioep->iep_auth, cco);
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
	dg_clnt_dropref(cl);

	if ((dgc->dgc_flags & DGC_FLG_SINGLE_BUF) != 0) {
		free(cco);
	} else {
		free(cco);
		free(dgc);
	}
}


static void
dg_sco_destroy(ar_svc_call_obj_t sco)
{
	ar_svc_xprt_t		*xp;
	ar_ioep_t	ioep;
	dg_ioep_t	*dep;
	dge_sco_t	*dgs;

	assert(sco != NULL);
	xp = sco->sco_xp;
	assert(xp != NULL);

	if (sco->sco_state != SCO_STATE_DEAD) {
		ioep = xp->xp_ioep;
		assert(ioep != NULL);
		dep = (dg_ioep_t *)ioep->iep_drv_arg;
		assert(dep != NULL);
	} else {
		dep = NULL;
		ioep = NULL;
	}

	dgs = (dge_sco_t *)sco->sco_lower;
	assert(dgs != NULL);
	
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
	dg_xp_dropref(xp);

	if (dgs->dgs_cbuf) {
		free(dgs->dgs_cbuf);
	}
	dgs->dgs_cbuf = NULL;
	if (dgs->dgs_addr.buf) {
		free(dgs->dgs_addr.buf);
	}
	dgs->dgs_addr.buf = NULL;
	free(sco);
}


static void
dg_xp_destroy(ar_svc_xprt_t *xp)
{
	ar_svc_call_obj_t	sco;
	ar_ioep_t	ioep;
	dg_ioep_t	*dep;

	assert(xp != NULL);
	
	xp->xp_flags |= XP_FLG_DESTROY;
	xp->xp_refcnt++;	/* for safety */

	if (xp->xp_queued_err < 0) {
		/* set a generic error */
		xp->xp_queued_err = EIO;
	}

	ioep = xp->xp_ioep;
	if (ioep) {
		dep = (dg_ioep_t *)ioep->iep_drv_arg;
		assert(dep != NULL);

		assert(ioep->iep_svc_ctx == xp);

		dg_ioep_bumpref(ioep);

		while ((sco = TAILQ_FIRST(&ioep->iep_svc_async_calls)) 
		       != NULL) {
			/* if the usr ref has not be released, we can't
			 * do anything more until the call is done or canceled
			 */
			dg_sco_destroy(sco);
		}

		while ((sco = TAILQ_FIRST(&ioep->iep_svc_replies)) != NULL) {
			dg_sco_destroy(sco);
		}

		while ((sco = TAILQ_FIRST(&ioep->iep_svc_cache)) != NULL) {
			dg_sco_destroy(sco);
		}

		ioep->iep_svc_ctx = NULL;
		xp->xp_ioep = NULL;

		if (TAILQ_EMPTY(&ioep->iep_client_list)) {
			/* Server context gone and no clients.  Remove 
			 * connection.
			 */
			dg_ioep_destroy(ioep);
		}

		dg_ioep_dropref(ioep);
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
dg_ioep_destroy(ar_ioep_t ioep)
{
	ar_ioctx_t	ioctx;
	dg_ioep_t	*dep;
	ar_client_t		*cl;
	ar_svc_xprt_t		*xp;

	assert(ioep != NULL);
	
	ioep->iep_flags |= IEP_FLG_DESTROY;
	dep = (dg_ioep_t *)ioep->iep_drv_arg;
	assert(dep != NULL);

	ioep->iep_refcnt++;	/* prevent it from going away */

	/* all ioep references come through the cnt or svc structures.
	 * If we kill those everything else should disappear.
	 */
	while ((cl = TAILQ_FIRST(&ioep->iep_client_list)) != NULL) {
		if (cl->cl_queued_err < 0 && dep->dep_sys_error > 0) {
			cl->cl_queued_err = dep->dep_sys_error;
		}
		dg_clnt_destroy(cl);
	}

	xp = ioep->iep_svc_ctx;
	if (xp) {
		/* this will destroy sco objects */
		if (xp->xp_queued_err < 0 && dep->dep_sys_error > 0) {
			xp->xp_queued_err = dep->dep_sys_error;
		}
		dg_xp_destroy(xp);
	}

	ioctx = ioep->iep_ioctx;
	if (ioctx) {
		TAILQ_REMOVE(&ioctx->icx_ep_list, ioep, iep_listent);
		ioep->iep_ioctx = NULL;
	}

#ifdef HAVE_LIBEVENT
	/* delete and free up monitored event */
	if (ioep->iep_event) {
		event_del(ioep->iep_event);
		event_free(ioep->iep_event);
		ioep->iep_event = NULL;
	}
#endif
	
	/* close the fd immediately */
	if (dep->dep_fd >= 0) {
		close(dep->dep_fd);
	}
	dep->dep_fd = -1;

	/* release our reference */
	ioep->iep_refcnt--;

	if (ioep->iep_refcnt > 0) {
		/* not yet able to really clean up the structure */
		return;
	}

	io_dg_ep_destroy(ioep);
}


static void
dg_clnt_bumpref(ar_client_t *cl)
{
	assert(cl != NULL);
	cl->cl_refcnt++;
}

static void
dg_clnt_dropref(ar_client_t *cl)
{
	assert(cl != NULL);
	cl->cl_refcnt--;
	if (cl->cl_refcnt <= 0  &&
	    (cl->cl_flags & CLNT_FLG_DESTROY) != 0) {
		dg_clnt_destroy(cl);
	}
}

static void
clnt_dg_call_dropref(ar_client_t *cl, ar_clnt_call_obj_t cco)
{
	dg_cco_dropref(cco);
}

static void
dg_cco_bumpref(ar_clnt_call_obj_t cco)
{
	assert(cco != NULL);
	cco->cco_refcnt++;
}

static void
dg_cco_dropref(ar_clnt_call_obj_t cco)
{
	assert(cco != NULL);
	cco->cco_refcnt--;
	if (cco->cco_refcnt <= 0 &&
	    (cco->cco_flags & CCO_FLG_DESTROY) != 0) {
		dg_cco_destroy(cco);
	}
}

static void
dg_sco_bumpref(ar_svc_call_obj_t sco)
{
	assert(sco != NULL);
	sco->sco_refcnt++;
}

static void
dg_sco_dropref(ar_svc_call_obj_t sco)
{
	assert(sco != NULL);
	sco->sco_refcnt--;
	if (sco->sco_refcnt <= 0 &&
	    (sco->sco_flags & SCO_FLG_DESTROY) != 0) {
		dg_sco_destroy(sco);
	}
}

static void
dg_xp_bumpref(ar_svc_xprt_t *xp)
{
	assert(xp != NULL);
	xp->xp_refcnt++;
}

static void
dg_xp_dropref(ar_svc_xprt_t *xp)
{
	assert(xp != NULL);
	xp->xp_refcnt--;
	if (xp->xp_refcnt <= 0 && 
	    (xp->xp_flags & XP_FLG_DESTROY) != 0) {
		dg_xp_destroy(xp);
	}
}

static void
dg_ioep_bumpref(ar_ioep_t ioep)
{
	assert(ioep != NULL);
	ioep->iep_refcnt++;
}

static void
dg_ioep_dropref(ar_ioep_t ioep)
{
	assert(ioep != NULL);
	ioep->iep_refcnt--;
	if (ioep->iep_refcnt <= 0 && 
	    (ioep->iep_flags & IEP_FLG_DESTROY) != 0) {
		dg_ioep_destroy(ioep);
	}
}


static int
dg_syscreat_err(arpc_createerr_t *errp, int err)
{
	if (errp) {
		ar_errno2err(&errp->cf_error, err);
		errp->cf_stat = errp->cf_error.re_status;
	}
	return err;
}

static void
dg_queue_syserror(dg_ioep_t *dep, int err)
{
	if (dep->dep_sys_error <= 0) {
		dep->dep_sys_error = err;
	}
}

static void
dg_syserror(dg_ioep_t *dep, int err)
{
	ar_ioep_t	ioep;

	assert(dep != NULL);

	if (dep->dep_sys_error <= 0) {
		dep->dep_sys_error = err;
	}
	ioep = dep->dep_ioep;

	dg_ioep_destroy(ioep);
}


static int
dg_ioep_tx_xdr(dg_ioep_t *dep, arpc_addr_t *addr, 
	       axdrproc_t xproc, void *xarg)
{
	axdr_ret_t ret;
	char *buf;
	int len;
	axdr_state_t xdr;
	ar_ioep_t ioep;
	struct sockaddr *sa;
	socklen_t salen;
	int err;
	
	if (!dep || !xproc) {
		return EINVAL;
	}

	ioep = dep->dep_ioep;
	if (!ioep) {
		return EINVAL;
	}

	axdrmem_create(&xdr, dep->dep_buf, dep->dep_bufsz, AXDR_ENCODE);
	ret = (*xproc)(&xdr, xarg);
	if (ret != AXDR_DONE) {
		axdr_destroy(&xdr);
		return EPARSE;
	}
	buf = dep->dep_buf;
	len = axdr_getpos(&xdr);
	axdr_destroy(&xdr);

	if (dep->dep_connect) {
		sa = NULL;
		salen = 0;
	} else if (addr) {
		sa = (struct sockaddr *)addr->buf;
		salen = addr->len;
	} else {
		return EINVAL;
	}

	err = sendto(dep->dep_fd, buf, len, 0, sa, salen);
	if (err < 0) {
		err = errno;
	} else {
		err = 0;
	}

	return err;
}

static int
dg_cl_tx(ar_clnt_call_obj_t cco)
{
	dge_call_t *dgc;
	dg_ioep_t *dep;
	ar_client_t *cl;
	axdr_ret_t ret;
	char *buf;
	int len;
	axdr_state_t xdr;
	ar_ioep_t ioep;
	struct sockaddr *sa;
	socklen_t salen;
	int err;

	if (!cco) {
		return EINVAL;
	}

	dgc = (dge_call_t *)cco->cco_lower;
	cl = cco->cco_client;
	if (!dgc || !cl) {
		return EINVAL;
	}

	ioep = cl->cl_ioep;
	if (!ioep) {
		return EINVAL;
	}
	dep = (dg_ioep_t *)ioep->iep_drv_arg;
	if (!dep) {
		return EINVAL;
	}

	switch (cco->cco_rtype) {
	case CLNT_ARGS_TYPE_XDR:
		axdrmem_create(&xdr, dep->dep_buf, dep->dep_bufsz, AXDR_ENCODE);
		ret = axdr_msg(&xdr, &cco->cco_call);
		if (ret != AXDR_DONE) {
			axdr_destroy(&xdr);
			return EPARSE;
		}
		buf = dep->dep_buf;
		len = axdr_getpos(&xdr);
		axdr_destroy(&xdr);
		break;
	case CLNT_ARGS_TYPE_BUF:
		buf = cco->cco_args.cco_buffer.buf;
		len = cco->cco_args.cco_buffer.len;
		break;
	default:
		return EINVAL;
	}

	if (dep->dep_connect) {
		sa = NULL;
		salen = 0;
	} else {
		sa = (struct sockaddr *)&dep->dep_raddr.buf;
		salen = dep->dep_raddr.len;
	}

	err = sendto(dep->dep_fd, buf, len, 0, sa, salen);
	if (err < 0) {
		err = errno;
	} else {
		err = 0;
	}

	return err;
}

static void
cco_syserror(ar_clnt_call_obj_t cco, int err)
{
	arpc_err_t result;

	ar_errno2err(&result, err);
	cco->cco_rpc_err = result;
	if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
		/* steal back usr reference, after notify */
		cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
		(*cco->cco_cb)(cco, cco->cco_cb_arg, &result, NULL);
		dg_cco_destroy(cco);
		/* actually drop usr ref */
		dg_cco_dropref(cco);	
	} else {
		dg_cco_destroy(cco);
	}
}

static void
clnt_dg_reauth(ar_client_t *cl, ar_clnt_call_obj_t cco)
{
	struct timespec	cur;
	ar_stat_t	cerr;
	arpc_err_t	result;
	dge_call_t	*dgc;
	ar_ioep_t	ioep;
	int		err;

	if (!cl || !cco) {
		return;
	}
	
	dgc = (dge_call_t *)cco->cco_lower;
	dg_clnt_bumpref(cl);

	ioep = cl->cl_ioep;
	if (!ioep) {
		cerr = ARPC_CANTCONNECT;
		goto error;
	}

	err = ar_clnt_cco_reauth(ioep->iep_auth, cco);
	if (err != 0) {
		cerr = ARPC_AUTHERROR;
		goto error;
	}

	dg_cl_tx(cco);
	dgc->dgc_retran_count++;

	dg_clnt_dropref(cl);

	ar_gettime(&cur);
	tspecadd(&dgc->dgc_retran_interval, &cur, &dgc->dgc_retran_limit);

	return;
 error:
	if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
		cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
		cco->cco_rpc_err.re_status = cerr;
		result = cco->cco_rpc_err;
		(*cco->cco_cb)(cco, cco->cco_cb_arg, &result, NULL);
		dg_cco_destroy(cco);
		dg_cco_dropref(cco);
	} else {
		dg_cco_destroy(cco);
	}
	dg_clnt_dropref(cl);
}

static void
dg_retransmit(ar_clnt_call_obj_t cco)
{
	dge_call_t	*dgc;
	int		err;

	dgc = (dge_call_t *)cco->cco_lower;

	err = dg_cl_tx(cco);
	if (err != 0) {
		cco_syserror(cco, err);
		return;
	}

	if (dgc->dgc_retran_interval.tv_sec < RPC_MAX_BACKOFF) {
		tspecadd(&dgc->dgc_retran_interval, &dgc->dgc_retran_interval,
			 &dgc->dgc_retran_interval);
	}
	tspecadd(&dgc->dgc_retran_interval, &dgc->dgc_retran_limit, 
		 &dgc->dgc_retran_limit);
	dgc->dgc_retran_count++;

	return;
}

static int 
dg_read_check(ar_ioctx_t ioctx, dg_ioep_t *dep, ar_ioep_t ep)
{
	ar_clnt_call_obj_t	cco;
	ar_svc_call_obj_t	sco;
	dge_sco_t		*dge;
	int			ret;
	int			inlen;
	axdr_state_t		xdrs;
	axdr_ret_t		rval;
	struct sockaddr_storage ss;
	socklen_t		slen;
	arpc_addr_t 		nbuf;
	arpc_msg_t		msg;
	arpc_err_t		result;

	memset(&ss, 0, sizeof(ss));
	slen = sizeof(ss);

	ret = recvfrom(dep->dep_fd, dep->dep_buf, dep->dep_bufsz, 0, 
		       (struct sockaddr *)&ss, &slen);
	if (ret < 0) {
		ret = errno;
		switch (ret) {
		case EAGAIN:
		case ENETUNREACH:
		case ENETRESET:
		case ECONNABORTED:
		case ECONNRESET:
		case ESHUTDOWN:
		case EHOSTUNREACH:
		case EADDRNOTAVAIL:
		case EINTR:
			ret = EAGAIN;
			break;
		default:
			dg_syserror(dep, ret);
			break;
		}
		return ret;
	}
	if (ret == 0) {
		/* empty */
		return 0;
	}
	inlen = ret;

	nbuf.buf = (char *)&ss;
	nbuf.len = slen;
	nbuf.maxlen = slen;

	axdrmem_create(&xdrs, dep->dep_buf, inlen, AXDR_DECODE);
	memset(&msg, 0, sizeof(msg));

	rval = axdr_msg(&xdrs, &msg);
	if (rval != AXDR_DONE) {
		/* unable to decode header info. Just ignore the msg */
		axdr_destroy(&xdrs);
		return 0;
	}

	/* HACK: FIXME */
	dep->dep_cur_addr = &nbuf;

	switch (msg.arm_direction) {
	case AR_REPLY:	
		cco = NULL;
		ar_clnt_handle_reply(&xdrs, ep, &msg, &cco);
		if (cco) {
			dg_cco_bumpref(cco);
			if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
				cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
				dg_cco_dropref(cco);
				result = cco->cco_rpc_err;
				(*cco->cco_cb)(cco, cco->cco_cb_arg, &result,
					       cco->cco_resp);
			}
			dg_cco_destroy(cco);
			dg_cco_dropref(cco);
		}
		break;
	case AR_CALL:
		sco = NULL;
		ar_svc_handle_call(&xdrs, ep, &msg, &sco);
		if (sco) {
			dge = (dge_sco_t *)sco->sco_lower;

			/* need to xmit result */
			dg_ioep_tx_xdr(dep, &nbuf, (axdrproc_t)&axdr_msg,
				       &sco->sco_reply);
			/* FIXME: cache results??? */
			dg_sco_destroy(sco);

			break;
		}

		/* save off source address so we know where to 
		 * send the reply. 
		 */
		TAILQ_FOREACH(sco, &ep->iep_svc_async_calls, sco_listent) {
			dge = (dge_sco_t *)sco->sco_lower;
			if (sco->sco_req.rq_xid == msg.arm_xid) {
				/* found it, add in the addr */
				if (dge->dgs_addr.buf) {
					free(dge->dgs_addr.buf);
				}
				dge->dgs_addr.buf = malloc(slen);
				if (dge->dgs_addr.buf) {
					memcpy(dge->dgs_addr.buf, &ss, slen);
					dge->dgs_addr.len = slen;
					dge->dgs_addr.maxlen = slen;
				} else {
					dge->dgs_addr.len = 0;
					dge->dgs_addr.maxlen = 0;
				}
			}
		}
		break;
	default:
		break;
	}

	dep->dep_cur_addr = NULL;

	axdr_free((axdrproc_t)axdr_msg, &msg);
	axdr_destroy(&xdrs);
	return 0;
}

static void
dg_read(ar_ioctx_t ioctx, dg_ioep_t *dep, ar_ioep_t ep)
{
	int err;
	
	if (!ioctx || !dep || !ep) {
		return;
	}

	while ((dep->dep_flags & DEP_FLG_FLOWCTL) == 0) {
		err = dg_read_check(ioctx, dep, ep);
		if (err != 0 && err != EAGAIN) {
			dg_syserror(dep, err);
			break;
		}
		if (err == EAGAIN || 
		    (ep->iep_flags & IEP_FLG_DESTROY) != 0) {
			break;
		}
	}
}


static void
dg_setup(ar_ioep_t ep, struct pollfd *pfd, int *timeoutp)
{
	ar_clnt_call_obj_t	cco;
	ar_svc_call_obj_t	sco;
	dge_sco_t	*dgs;
	dge_call_t	*dgc;
	struct timespec cur;
	struct timespec diff;
	dg_ioep_t	*dep;
	int		period;
	int		timeout;

	if (pfd) {
		pfd->fd = -1;
		pfd->events = 0;
	}

	if (timeoutp) {
		*timeoutp = 0;
	}

	if (!timeoutp || !pfd || !ep || ep->iep_type != IOEP_TYPE_DG) {
		return;
	}

	dep = (dg_ioep_t *)ep->iep_drv_arg;
	if (!dep) {
		return;
	}

	if (dep->dep_sys_error > 0) {
		return;
	}

	if (dep->dep_fd < 0) {
		dg_queue_syserror(dep, ENOTCONN);
		return;
	}

	pfd->fd = dep->dep_fd;
	if ((dep->dep_flags & DEP_FLG_FLOWCTL) == 0) {
		pfd->events |= POLLIN;
	}

	timeout = -1;

	/* accumulate timeouts:
	 * 1. call timeouts
	 * 2. svc response timers
	 */
	ar_gettime(&cur);
	
	TAILQ_FOREACH(cco, &ep->iep_clnt_calls, cco_listent) {
		if (cco->cco_state != CCO_STATE_PENDING &&
		    cco->cco_state != CCO_STATE_RUNNING) {
			continue;
		}
		tspecadd(&cco->cco_timeout, &cco->cco_start, &diff);
		tspecsub(&diff, &cur, &diff);
		period = ar_time_to_ms(&diff);
		if (period < timeout || timeout < 0) {
			timeout = period;
		}
		dgc = (dge_call_t *)cco->cco_lower;
		tspecsub(&dgc->dgc_retran_limit, &cur, &diff);
		period = ar_time_to_ms(&diff);
		if (period < timeout || timeout < 0) {
			timeout = period;
		}
	}

	TAILQ_FOREACH(sco, &ep->iep_svc_cache, sco_listent) {
		dgs = (dge_sco_t *)sco->sco_lower;
		assert(sco->sco_state == SCO_STATE_CACHED);
		assert(dgs != NULL);

		tspecsub(&dgs->dgs_cache_timeout, &cur, &diff);
		period = ar_time_to_ms(&diff);
		if (period < timeout || timeout < 0) {
			timeout = period;
		}
	}

	*timeoutp = timeout;
}

static void
dg_dispatch(ar_ioep_t ep, struct pollfd *pfd)
{
	dge_call_t		*dgc;
	ar_svc_call_obj_t	sco;
	ar_svc_call_obj_t	sconext;
	dg_ioep_t		*dep;
	dge_sco_t		*dgs;
	ar_ioctx_t		ioctx;
	ar_clnt_call_obj_t	cco;
	ar_clnt_call_obj_t	cconext;
	struct timespec		diff;
	struct timespec		cur;
	struct timespec		zero;
	arpc_err_t		result;

	if (!pfd) {
		return;
	}

	if (!ep || ep->iep_type != IOEP_TYPE_DG) {
		return;
	}


	dep = (dg_ioep_t *)ep->iep_drv_arg;
	if (!dep) {
		return;
	}

	if (dep->dep_sys_error > 0) {
		dg_syserror(dep, dep->dep_sys_error);
		return;
	}

	ioctx = ep->iep_ioctx;
	if (dep->dep_fd < 0 || !ioctx) {
		dg_syserror(dep, EINVAL);
		return;
	}

	if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
		return;
	}

	if (pfd->revents & (POLLERR|POLLNVAL)) {
		dg_syserror(dep, EIO);
		return;
	}

	dg_ioep_bumpref(ep);

	if (pfd->revents & POLLIN) {
		dg_read(ioctx, dep, ep);
		if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
			goto cleanup;
		}
	}

	/* dispatch timeouts:
	 * 1. call timeouts
	 * 2. svc response timers
	 */
	ar_gettime(&cur);
	zero.tv_sec = 0;
	zero.tv_nsec = 0;
	
	cco = TAILQ_FIRST(&ep->iep_clnt_calls);
	if (cco) {
		dg_cco_bumpref(cco);
	}

	for (; cco; cco = cconext) {
		cconext = TAILQ_NEXT(cco, cco_listent);
		if (cconext) {
			dg_cco_bumpref(cconext);
		}
		if (cco->cco_state != CCO_STATE_PENDING &&
		    cco->cco_state != CCO_STATE_RUNNING) {
			dg_cco_dropref(cco);
			continue;
		}

		tspecadd(&cco->cco_timeout, &cco->cco_start, &diff);
		tspecsub(&diff, &cur, &diff);
		if (tspeccmp(&diff, &zero, >)) {
			dgc = (dge_call_t *)cco->cco_lower;
			tspecsub(&dgc->dgc_retran_limit, &cur, &diff);
			if (tspeccmp(&diff, &zero, <=)) {
				dg_retransmit(cco);
			}
			dg_cco_dropref(cco);
			continue;
		}

		cco->cco_rpc_err.re_status = ARPC_TIMEDOUT;
		if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
			/* steal back usr reference, after notify */
			cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
			result = cco->cco_rpc_err;
			(*cco->cco_cb)(cco, cco->cco_cb_arg, &result, NULL);
			/* actually drop usr ref */
			dg_cco_dropref(cco);
		}
		dg_cco_destroy(cco);
		dg_cco_dropref(cco);
	}

	for (sco = TAILQ_FIRST(&ep->iep_svc_cache); sco; sco = sconext) {
		sconext = TAILQ_NEXT(sco, sco_listent);
		dgs = (dge_sco_t *)sco->sco_lower;
		assert(sco->sco_state == SCO_STATE_CACHED);
		assert(dgs != NULL);

		tspecsub(&dgs->dgs_cache_timeout, &cur, &diff);
		if (tspeccmp(&diff, &zero, <=)) {
			dg_sco_destroy(sco);
		}
	}

 cleanup:
	dg_ioep_dropref(ep);
}

static void
dg_destroy(ar_ioep_t ep)
{
	dg_ioep_destroy(ep);
}

static int
dg_sendmsg(ar_ioep_t ep, arpc_msg_t *msg, ar_svc_call_obj_t sco)
{
	dg_ioep_t	*dep;
	dge_sco_t       *dge;
	struct sockaddr *sa;
	socklen_t	salen;
	axdr_ret_t	ret;
	axdr_state_t	xdr;
	char		*buf;
	int		len;
	int		err;

	if (!ep || !msg) {
		return EINVAL;
	}

	if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
		return EIO;
	}
	
	dep = (dg_ioep_t *)ep->iep_drv_arg;
	if (!dep) {
		return EINVAL;
	}

	axdrmem_create(&xdr, dep->dep_buf, dep->dep_bufsz, AXDR_ENCODE);
	ret = axdr_msg(&xdr, msg);
	buf = dep->dep_buf;
	len = axdr_getpos(&xdr);
	axdr_destroy(&xdr);
	
	if (ret != AXDR_DONE) {
		return EPARSE;
	}

	if (dep->dep_connect) {
		sa = NULL;
		salen = 0;
	} else if (sco) {
		dge = (dge_sco_t *)sco->sco_lower;
		if (dge->dgs_addr.len > 0) {
			sa = (struct sockaddr *)dge->dgs_addr.buf;
			salen = dge->dgs_addr.len;
		} else {
			sa = (struct sockaddr *)&dep->dep_raddr.buf;
			salen = dep->dep_raddr.len;
		}
	} else {
		sa = (struct sockaddr *)&dep->dep_raddr.buf;
		salen = dep->dep_raddr.len;
	}

	err = sendto(dep->dep_fd, buf, len, 0, sa, salen);
	if (err < 0) {
		err = errno;
	} else {
		err = 0;
	}

	return err;
}

static int
dg_add_client(ar_ioep_t ep, const arpcprog_t prog, const arpcvers_t vers,
	      ar_clnt_attr_t *attr, arpc_err_t *errp, ar_client_t **retp)
{
	ar_clnt_attr_t	lattr;
	dg_ioep_t	*dep;
	ar_client_t	*cl;
	int		err;
	ar_stat_t	stat;

	stat = ARPC_SUCCESS;
	if (!ep || retp) {
		stat = ARPC_ERRNO;
		err = EINVAL;
		goto error;
	}

	if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
		stat = ARPC_ERRNO;
		err = EIO;
		goto error;
	}

	dep = (dg_ioep_t *)ep->iep_drv_arg;
	if (!dep) {
		stat = ARPC_ERRNO;
		err = EINVAL;
		goto error;
	}

	if (!attr) {
		err = ar_clnt_attr_init(&lattr);
		if (err != 0) {
			stat = ARPC_ERRNO;
			goto error;
		}
		attr = &lattr;
	}


	/* create the client */
	cl = malloc(sizeof(*cl));
	if (!cl) {
		io_dg_ep_destroy(ep);
		stat = ARPC_ERRNO;
		err = ENOMEM;
		goto error;

	}

	memset(cl, 0, sizeof(*cl));

	cl->cl_ops = &dg_clnt_ops;
	cl->cl_refcnt = 1;
	cl->cl_ioep = ep;
	cl->cl_ioctx = ep->iep_ioctx;
	cl->cl_prog = prog;
	cl->cl_ver = vers;
	cl->cl_private = dep;
	cl->cl_defwait.tv_sec = CG_DEF_RPC_TIMEOUT_SECS;
	cl->cl_defwait.tv_nsec = CG_DEF_RPC_TIMEOUT_NSECS;
	cl->cl_queued_err = -1;

	/* FIXME: we need a per client private structure.  These should
	 * be in there...
	 */
	cl->cl_discon_cb = attr->ca_discon_cb;
	cl->cl_discon_cb_arg = attr->ca_discon_arg;

	/* add client to ioep */
	TAILQ_INSERT_TAIL(&ep->iep_client_list, cl, cl_listent);

	/* return client */
	*retp = cl;
	err = 0;

	if (attr->ca_conn_cb) {
		arpc_createerr_t cerr;

		/* udp is always connected, make the callback */
		memset(&cerr, 0, sizeof(cerr));
		cerr.cf_stat = ARPC_SUCCESS;
		(*attr->ca_conn_cb)(cl, attr->ca_conn_arg, &cerr);
	}
 error:
	if (attr == &lattr) {
		ar_clnt_attr_destroy(&lattr);
	}
	if (errp) {
		errp->re_status = stat;
		if (stat == ARPC_ERRNO) {
			errp->re_errno = err;
		}
	}
	return err;
}

#ifdef HAVE_LIBEVENT
/* dg_event_cb() is a callback function from the event.
 * it is very similar to dg_dispatch().
 */
static void
dg_event_cb(evutil_socket_t fd, short events, void *arg)
{
	dge_call_t		*dgc;
	ar_svc_call_obj_t	sco;
	ar_svc_call_obj_t	sconext;
	ar_ioep_t               ep;
	dg_ioep_t		*dep;
	dge_sco_t		*dgs;
	ar_ioctx_t		ioctx;
	ar_clnt_call_obj_t	cco;
	ar_clnt_call_obj_t	cconext;
	struct timespec		diff;
	struct timespec		cur;
	struct timespec		zero;
	arpc_err_t		result;

	ep = (ar_ioep_t)arg;

	if (!ep || ep->iep_type != IOEP_TYPE_DG) {
		return;
	}

	dep = (dg_ioep_t *)ep->iep_drv_arg;
	if (!dep) {
		return;
	}

	if (dep->dep_sys_error > 0) {
		dg_syserror(dep, dep->dep_sys_error);
		return;
	}

	ioctx = ep->iep_ioctx;
	if (dep->dep_fd < 0 || !ioctx) {
		dg_syserror(dep, EINVAL);
		return;
	}

	if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
		goto cleanup;
	}

	dg_ioep_bumpref(ep);

	if (events & EV_READ) {
		dg_read(ioctx, dep, ep);
		if ((ep->iep_flags & IEP_FLG_DESTROY) != 0) {
			goto cleanup;
		}
	}

	/* dispatch timeouts:
	 * 1. call timeouts
	 * 2. svc response timers
	 */
	ar_gettime(&cur);
	zero.tv_sec = 0;
	zero.tv_nsec = 0;
	
	cco = TAILQ_FIRST(&ep->iep_clnt_calls);
	if (cco) {
		dg_cco_bumpref(cco);
	}

	for (; cco; cco = cconext) {
		cconext = TAILQ_NEXT(cco, cco_listent);
		if (cconext) {
			dg_cco_bumpref(cconext);
		}
		if (cco->cco_state != CCO_STATE_PENDING &&
		    cco->cco_state != CCO_STATE_RUNNING) {
			dg_cco_dropref(cco);
			continue;
		}

		tspecadd(&cco->cco_timeout, &cco->cco_start, &diff);
		tspecsub(&diff, &cur, &diff);
		if (tspeccmp(&diff, &zero, >)) {
			dgc = (dge_call_t *)cco->cco_lower;
			tspecsub(&dgc->dgc_retran_limit, &cur, &diff);
			if (tspeccmp(&diff, &zero, <=)) {
				dg_retransmit(cco);
			}
			dg_cco_dropref(cco);
			continue;
		}

		cco->cco_rpc_err.re_status = ARPC_TIMEDOUT;
		if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
			/* steal back usr reference, after notify */
			cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
			result = cco->cco_rpc_err;
			(*cco->cco_cb)(cco, cco->cco_cb_arg, &result, NULL);
			/* actually drop usr ref */
			dg_cco_dropref(cco);
		}
		dg_cco_destroy(cco);
		dg_cco_dropref(cco);
	}

	for (sco = TAILQ_FIRST(&ep->iep_svc_cache); sco; sco = sconext) {
		sconext = TAILQ_NEXT(sco, sco_listent);
		dgs = (dge_sco_t *)sco->sco_lower;
		assert(sco->sco_state == SCO_STATE_CACHED);
		assert(dgs != NULL);

		tspecsub(&dgs->dgs_cache_timeout, &cur, &diff);
		if (tspeccmp(&diff, &zero, <=)) {
			dg_sco_destroy(sco);
		}
	}

 cleanup:
	dg_ioep_dropref(ep);
}

static int
dg_event_setup(ar_ioep_t ep, struct event_base *evbase)
{
	struct pollfd pfd;
	struct event *ev;
	short events;
	struct timespec ts;
	struct timeval tv;
	int timeout;

	if (!ep || ep->iep_type != IOEP_TYPE_DG) {
		return EINVAL;
	}

	/* call poll_setup routine for the fd and events */
	dg_setup(ep, &pfd, &timeout);

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
	ev = event_new(evbase, (evutil_socket_t)pfd.fd,
		       events, dg_event_cb, (void *)ep);
	/* monitor the event */
	tv.tv_sec = ts.tv_sec;
	tv.tv_usec = ts.tv_nsec / 1000;
	event_add(ev, &tv);

	ep->iep_event = ev;

	return 0;
	
}
#endif /* HAVE_LIBEVENT */

static int
clnt_dg_call(ar_client_t *cl, arpcproc_t proc, axdrproc_t xargs, void *argsp, 
	     bool_t inplace, axdrproc_t xres, void *resp, int ressize, 
	     ar_clnt_async_cb_t cb, void *cb_arg, struct timespec *tout, 
	     ar_clnt_call_obj_t *ccop)
{
	ar_clnt_call_obj_t	cco;
	dge_call_t		*dgc;
	dg_ioep_t		*dep;
	ar_ioep_t		ioep;
	int			len;
	int			err;
	arpc_err_t		result;
	

	if (!cl || !xargs || !cb || !ccop) {
		return EINVAL;
	}

	ioep = cl->cl_ioep;
	dep = (dg_ioep_t *)cl->cl_private;

	if (cl->cl_queued_err > 0) {
		return cl->cl_queued_err;
	}

	if (!ioep || !dep) {
		return ENOTCONN;
	}

	if (dep->dep_sys_error > 0) {
		return dep->dep_sys_error;
	}

	len = sizeof(*cco) + sizeof(dge_call_t);
	cco = malloc(len);
	if (!cco) {
		return ENOMEM;
	}
	memset(cco, 0, len);
	dgc = (dge_call_t *)&cco[1];

	err = ar_clnt_cco_init(cco, cl, ioep->iep_auth, &ioep->iep_xid_state, 
			       proc, xargs, argsp, inplace, xres, 
			       resp, ressize, cb, cb_arg, tout);
	if (err != 0) {
		free(cco);
		return err;
	}
	dgc->dgc_retran_interval = dep->dep_rtran;
	tspecadd(&dgc->dgc_retran_interval, &cco->cco_start, 
		 &dgc->dgc_retran_limit);
	dgc->dgc_retran_count = 0;
	dgc->dgc_flags = DGC_FLG_SINGLE_BUF;

	cco->cco_lower = dgc;

	err = dg_cl_tx(cco);
	if (err != 0) {
		ar_clnt_cco_cleanup(ioep->iep_auth, cco);
		free(cco);
		return err;
	}

	/* bump client reference for ref from cco */
	dg_clnt_bumpref(cl);

	TAILQ_INSERT_TAIL(&ioep->iep_clnt_calls, cco, cco_listent);
		
	*ccop = cco;

	if (!xres) {
		/* complete it immediately */
		dg_cco_bumpref(cco);
		if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
			cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
			dg_cco_dropref(cco);
			cco->cco_rpc_err.re_status = ARPC_SUCCESS;
			result = cco->cco_rpc_err;
			(*cco->cco_cb)(cco, cco->cco_cb_arg, &result, NULL);
		}
		dg_cco_destroy(cco);
		dg_cco_dropref(cco);
	}

	return 0;
}

static void
clnt_dg_destroy(ar_client_t *cl)
{
	if (!cl) {
		return;
	}

	dg_clnt_bumpref(cl);

	if ((cl->cl_flags & CLNT_FLG_USRREF_DEC) == 0) {
		cl->cl_flags |= CLNT_FLG_USRREF_DEC;
		dg_clnt_dropref(cl);
	}

	dg_clnt_destroy(cl);
	dg_clnt_dropref(cl);
}


static bool_t
clnt_dg_control(ar_client_t *cl, u_int cmd, void *info)
{
	struct timespec ts;
	arpc_addr_t *nb;
	ar_ioep_t ioep;
	dg_ioep_t *dep;
	int val;
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
	dep = (dg_ioep_t *)ioep->iep_drv_arg;
	assert(dep != NULL);

	/* for other requests which use info */
	if (info == NULL) {
		return FALSE;
	}

	if (dep->dep_sys_error > 0) {
		return FALSE;
	}

	switch (cmd) {
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
		nb = (arpc_addr_t *)info;
		nb->len = nb->maxlen;
		err = getpeername(dep->dep_fd, (struct sockaddr *)nb->buf,
				  &nb->len);
		if (err < 0) {
			return FALSE;
		}
		break;
	case AR_CLGET_LOCAL_ADDR:
		nb = (arpc_addr_t *)info;
		nb->len = nb->maxlen;
		err = getsockname(dep->dep_fd, (struct sockaddr *)nb->buf,
				  &nb->len);
		if (err < 0) {
			return FALSE;
		}
		break;
	case AR_CLSET_RETRY_TIMEOUT:
		ts.tv_sec = ((struct timeval *)info)->tv_sec;
		ts.tv_nsec = ((struct timeval *)info)->tv_usec * 1000;

		if (ar_time_not_ok(&ts)) {
			return (FALSE);
		}
		dep->dep_rtran = ts;
		break;
	case AR_CLGET_RETRY_TIMEOUT:
		ts = dep->dep_rtran;
		((struct timeval *)info)->tv_sec = ts.tv_sec;
		((struct timeval *)info)->tv_usec = ts.tv_nsec / 1000;
		break;
	case AR_CLGET_FD:
		*((int *)info) = dep->dep_fd;
		break;
	case AR_CLGET_SVC_ADDR:
		/* The caller should not free this memory area */
		*((arpc_addr_t *)info) = dep->dep_raddr;
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
	case AR_CLSET_CONNECT:
		val = *(int *)info;
		if (dep->dep_connect && !val) {
			/* can't unconnect */
			return FALSE;
		}
		if (!dep->dep_connect && val) {
			/* need to connect */
			err = connect(dep->dep_fd,
				      (struct sockaddr *)dep->dep_raddr.buf, 
				      dep->dep_raddr.len);
			if (err < 0) {
				err = errno;
				return FALSE;
			}
			dep->dep_connect = TRUE;
		}
		break;
	default:
		return ar_clnt_control_default(cl, cmd, info);
	}
	return TRUE;
}

static int
clnt_dg_cancel(ar_client_t *cl, ar_clnt_call_obj_t cco)
{
	if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
		cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
		dg_cco_destroy(cco);
		dg_cco_dropref(cco);
	} else {
		dg_cco_destroy(cco);
	}
	return 0;
}

static int
clnt_dg_handoff(ar_client_t *src, ar_client_t *dst, cco_list_t *msglist,
		struct ar_xid_state_s *xstate,
		arpc_createerr_t *errp)
{
	ar_ioep_t		ioep;
	ar_clnt_call_obj_t	cco;
	dge_call_t		*dgc;
	dg_ioep_t		*dep;
	struct timespec		now;
	cco_list_t		list;
	int			err;

	if (!src || !dst || !msglist || !xstate) {
		return dg_syscreat_err(errp, EINVAL);
	}
	
	if (src->cl_ops != &dg_clnt_ops) {
		return dg_syscreat_err(errp, EINVAL);
	}

	ioep = src->cl_ioep;
	if (!ioep) {
		if (errp) {
			errp->cf_stat = ARPC_XPRTFAILED;
		}
		return ENOTCONN;
	}

	dep = (dg_ioep_t *)ioep->iep_drv_arg;
	assert(dep != NULL);

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
		dgc = (dge_call_t *)malloc(sizeof(*dgc));
		if (!dgc) {
			err = ENOMEM;
			break;
		}
		memset(dgc, 0, sizeof(*dgc));

		dgc->dgc_retran_interval = dep->dep_rtran;
		tspecadd(&dgc->dgc_retran_interval, &now, 
			 &dgc->dgc_retran_limit);
		dgc->dgc_retran_count = 0;
		dgc->dgc_flags = 0;
		
		/* Remove from the callers list */
		TAILQ_REMOVE(msglist, cco, cco_listent);
		
		cco->cco_lower = dgc;
		TAILQ_INSERT_TAIL(&list, cco, cco_listent);
	}

	if (err != 0) {
		while ((cco = TAILQ_LAST(&list, cco_list_s)) != NULL) {
			TAILQ_REMOVE(&list, cco, cco_listent);

			dgc = (dge_call_t *)cco->cco_lower;
			cco->cco_lower = NULL;
			free(dgc);

			TAILQ_INSERT_HEAD(msglist, cco, cco_listent);
		}

		return dg_syscreat_err(errp, err);
	}

	/* move existing calls to new client.  Usually these don't
	 * exist, because the src client handle has not been exported
	 * out of the library.
	 */
	TAILQ_FOREACH(cco, &ioep->iep_clnt_calls, cco_listent) {
		if (cco->cco_client == src) {
			src->cl_refcnt--;
			cco->cco_client = dst;
			dg_clnt_bumpref(dst);
		}
	}

	/* now that all the allocations that can fail are done, 
	 * make an atomic switch of all outstanding calls.
	 */
	TAILQ_REMOVE(&ioep->iep_client_list, src, cl_listent);
	
	dst->cl_ops = &dg_clnt_ops;
	dst->cl_ioep = ioep;
	dst->cl_ioctx = src->cl_ioctx;
	dst->cl_private = dep;
	dst->cl_prog = src->cl_prog;
	dst->cl_ver = src->cl_ver;
	dst->cl_defwait = src->cl_defwait;
	dst->cl_discon_cb = src->cl_discon_cb;
	dst->cl_discon_cb_arg = src->cl_discon_cb_arg;

	TAILQ_INSERT_TAIL(&ioep->iep_client_list, dst, cl_listent);

	/* move xid state over, so we maintain correction call # space */
	if (xstate) {
		ioep->iep_xid_state = *xstate;
	}

	src->cl_ops = NULL;
	src->cl_ioep = NULL;
	src->cl_ioctx = NULL;
	src->cl_private = NULL;

	/* should be 1 remaining user reference */
	assert(src->cl_refcnt == 1);

	/* our responsibilty to free src client structure */
	free(src);

	/* transfer outstanding calls.  We do this last because we 
	 * do a dg_cl_tx and the dst client needs to be completely setup for
	 * this to work right.
	 */
	while ((cco = TAILQ_FIRST(&list)) != NULL) {
		TAILQ_REMOVE(&list, cco, cco_listent);

		/* associate call with ioep */
		TAILQ_INSERT_TAIL(&ioep->iep_clnt_calls, cco, cco_listent);

		cco->cco_client = dst;
		cco->cco_state = CCO_STATE_PENDING;
		cco->cco_start = now;

		/* bump client reference for ref from cco */
		dg_clnt_bumpref(dst);

		dg_cl_tx(cco);
	}

	return 0;
}

#if 0 /* FIXME! */
		if (setsockopt(fd, IPPROTO_IPV6,
			       IPV6_V6ONLY, &on, sizeof on) < 0) {
			syslog(LOG_ERR,
			       "can't set v6-only binding for "
			       "udp6 socket: %m");
			continue;
		}
#endif

static int
vc_add_svc_ctx(ar_ioep_t ioep, ar_svc_attr_t *attr)
{
	ar_svc_xprt_t			*xp;

	if (!ioep || ioep->iep_svc_ctx) {
		return EINVAL;
	}

	xp = malloc(sizeof(*xp));
	if (!xp) {
		return ENOMEM;
	}
	memset(xp, 0, sizeof(*xp));

	xp->xp_refcnt = 1;	/* user reference */
	xp->xp_flags = 0;
	xp->xp_ops = &dg_xp_ops;
	xp->xp_ioep = ioep;
	xp->xp_ioctx = ioep->iep_ioctx;
	xp->xp_queued_err = -1;

	if (attr) {
		xp->xp_error_cb = attr->sa_error_cb;
		xp->xp_error_arg = attr->sa_error_arg;
	}

	ioep->iep_svc_ctx = xp;
	ioep->iep_flags |= IEP_FLG_ALLOW_SVC;
	return 0;
}


static int
io_dg_ep_create(ar_ioctx_t ctx, int sendsz, int recvsz, 
		ar_clnt_attr_t *attr, ar_svc_attr_t *sattr,
		arpc_err_t *errp, ar_ioep_t *ioepp)
{
	ar_ioep_t		ioep;
	dg_ioep_t		*dep;
	const char		*prefix;
	FILE			*fp;
	int			size;
	int			len;
	int			err;

	if (!ioepp) {
		err = EINVAL;
		goto cleanup;
	}

	size = recvsz;
	if (sendsz > size) {
		size = sendsz;
	}

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

	len = sizeof(*dep) + sizeof(*ioep) + size;
	ioep = malloc(len);
	if (!ioep) {
		err = ENOMEM;
		goto cleanup;
	}
	memset(ioep, 0, len);
	dep = (dg_ioep_t *)&ioep[1];
	
	err = ar_ioep_init(ioep, ctx, IOEP_TYPE_DG, &dg_ep_driver, dep,
			   fp, prefix);
	if (err != 0) {
		free(ioep);
		goto cleanup;
	}

	dep->dep_ioep = ioep;
	dep->dep_connect = FALSE;
	dep->dep_fd = -1;
	dep->dep_rtran.tv_sec = DGE_BASE_RETRAN_SECS;
	dep->dep_rtran.tv_nsec = DGE_BASE_RETRAN_NSECS;
	dep->dep_buf = (char *)&dep[1];
	dep->dep_bufsz = size;
	dep->dep_sys_error = -1;

	*ioepp = ioep;
	err = 0;
cleanup:
	if (errp) {
		ar_errno2err(errp, err);
	}
	return err;
}

static void
io_dg_ep_destroy(ar_ioep_t ioep)
{
	dg_ioep_t	*dep;

	if (!ioep) {
		return;
	}

	dep = (dg_ioep_t *)ioep->iep_drv_arg;

	ar_ioep_cleanup(ioep);

	if (dep->dep_raddr.buf) {
		free(dep->dep_raddr.buf);
		dep->dep_raddr.buf = NULL;
	}

	if (dep->dep_fd >= 0) {
		close(dep->dep_fd);
	}
	dep->dep_fd = -1;

	free(ioep);
}
		

int
ar_clnt_dg_create(ar_ioctx_t ctx, const arpc_addr_t *svcaddr,
		  const arpcprog_t prog, const arpcvers_t ver,  
		  ar_clnt_attr_t *attr, arpc_createerr_t *errp, 
		  ar_client_t **retp)
{
	arpc_createerr_t 	cerr;
	ar_clnt_attr_t		lattr;
	dg_ioep_t      		*dep;
	ar_ioep_t		ioep;
	int			sendsz;
	int			recvsz;
	struct sockaddr_in	*in;
	ar_client_t		*cl;
	int			flags;
	int			ret;
	int			err;
	arpc_err_t		aerr;

	if (!ctx || !svcaddr || !svcaddr->buf || !retp) {
		err = EINVAL;
		goto error;
	}

	if (!attr) {
		err = ar_clnt_attr_init(&lattr);
		if (err != 0) {
			goto error;
		}
		attr = &lattr;
	}

	if (svcaddr->len < sizeof(*in)) {
		err = EINVAL;
		goto error;
	}
	in = (struct sockaddr_in *)svcaddr->buf;
	switch (in->sin_family) {
	case AF_INET:
		break;
	case AF_INET6:
		if (svcaddr->len < sizeof(struct sockaddr_in6)) {
			err = EINVAL;
			goto error;
		}
		break;
	default:
		err = EINVAL;
		goto error;
	}

	sendsz = ar_get_t_size(in->sin_family, 
			       IPPROTO_TCP, attr->ca_sendsz);
	recvsz = ar_get_t_size(in->sin_family, 
			       IPPROTO_TCP, attr->ca_recvsz);

	/* create the ioep */
	err = io_dg_ep_create(ctx, sendsz, recvsz, attr, NULL, &aerr, &ioep);
	if (err != 0) {
		if (errp) {
			errp->cf_error = aerr;
			errp->cf_stat = aerr.re_status;
		}
		goto cleanup;
	}

	/* get the connection started */
	dep = (dg_ioep_t *)ioep->iep_drv_arg;

	/* dg clients default to connected mode operation */
	dep->dep_connect = TRUE;

	/* create the client */
	cl = malloc(sizeof(*cl));
	if (!cl) {
		io_dg_ep_destroy(ioep);
		err = ENOMEM;
		goto error;
	}

	memset(cl, 0, sizeof(*cl));

	cl->cl_ops = &dg_clnt_ops;
	cl->cl_refcnt = 1;
	cl->cl_ioep = ioep;
	cl->cl_ioctx = ctx;
	cl->cl_prog = prog;
	cl->cl_ver = ver;
	cl->cl_private = dep;
	cl->cl_defwait.tv_sec = CG_DEF_RPC_TIMEOUT_SECS;
	cl->cl_defwait.tv_nsec = CG_DEF_RPC_TIMEOUT_NSECS;
	cl->cl_queued_err = -1;

	/* FIXME: we need a per client private structure.  These should
	 * be in there...
	 */
	cl->cl_discon_cb = attr->ca_discon_cb;
	cl->cl_discon_cb_arg = attr->ca_discon_arg;

	ret = socket(in->sin_family, SOCK_DGRAM, 0);
	if (ret < 0) {
		err = errno;
		io_dg_ep_destroy(ioep);
		free(cl);
		goto error;
	}
	dep->dep_fd = ret;

	flags = fcntl(dep->dep_fd, F_GETFL, 0);
	if (flags < 0) {
		err = errno;
		io_dg_ep_destroy(ioep);
		free(cl);
		goto error;
	}
	flags |= O_NONBLOCK|O_NDELAY;
	ret = fcntl(dep->dep_fd, F_SETFL, flags);
	if (ret != 0) {
		err = errno;
		io_dg_ep_destroy(ioep);
		free(cl);
		goto error;
	}

	ret = fcntl(dep->dep_fd, F_SETFD, FD_CLOEXEC);
	if (ret != 0) {
		err = errno;
		io_dg_ep_destroy(ioep);
		free(cl);
		goto error;
	}

	if (dep->dep_connect) {
		err = connect(dep->dep_fd, (struct sockaddr *)svcaddr->buf,
			      svcaddr->len);
		if (err < 0) {
			err = errno;
			if (err != EINPROGRESS) {
				/* on TLI signaled socket setups, we get
				 * and EAGAIN, even on dg connections...
				 */
				free(cl);
				io_dg_ep_destroy(ioep);
				goto error;
			}
		}			
	}

	dep->dep_raddr.buf = malloc(svcaddr->len);
	if (!dep->dep_raddr.buf) {
		free(cl);
		io_dg_ep_destroy(ioep);
		err = ENOMEM;
		goto error;
	}
	memcpy(dep->dep_raddr.buf, svcaddr->buf, svcaddr->len);
	dep->dep_raddr.len = svcaddr->len;
	dep->dep_raddr.maxlen = svcaddr->len;

	/* add client to ioep */
	TAILQ_INSERT_TAIL(&ioep->iep_client_list, cl, cl_listent);

	/* add ioep to ioctx */
	TAILQ_INSERT_TAIL(&ctx->icx_ep_list, ioep, iep_listent);

	if ((attr->ca_flags & CA_FLG_ALLOW_SVC) != 0) {
		err = vc_add_svc_ctx(ioep, NULL);
		if (err != 0) {
			/* full destroy at this point, through the clnt
			 * struture.
			 */
			ar_clnt_destroy(cl);
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
	err = 0;

	if (attr->ca_conn_cb) {
		/* udp is always connected, make the callback */
		memset(&cerr, 0, sizeof(cerr));
		cerr.cf_stat = ARPC_SUCCESS;
		cerr.cf_error.re_status = ARPC_SUCCESS;
		(*attr->ca_conn_cb)(cl, attr->ca_conn_arg, &cerr);
	}

error:
	if (errp) {
		ar_errno2err(&errp->cf_error, err);
		errp->cf_stat = errp->cf_error.re_status;
	}
cleanup:
	if (attr == &lattr) {
		ar_clnt_attr_destroy(&lattr);
	}
	return err;
}

static void
dg_cache_makeroom(ar_ioep_t ep, int len)
{
	dg_ioep_t	*dep;
	int		totalsize;
	ar_svc_call_obj_t	sco;
	dge_sco_t	*dgs;


	if (!ep) {
		return;
	}

	dep = (dg_ioep_t *)ep->iep_drv_arg;
	if (dep->dep_cache_bytes <= 0) {
		return;
	}
	
	totalsize = 0;
	TAILQ_FOREACH(sco, &ep->iep_svc_cache, sco_listent) {
		dgs = (dge_sco_t *)sco->sco_lower;
		totalsize += dgs->dgs_cbufsz;
	}

	while (totalsize > 0 && totalsize + len > dep->dep_cache_bytes) {
		/* should be in lru order */
		sco = TAILQ_FIRST(&ep->iep_svc_cache);
		if (!sco) {
			break;
		}
		dgs = (dge_sco_t *)sco->sco_lower;
		assert(sco->sco_state == SCO_STATE_CACHED);
		assert(dgs != NULL);
		totalsize -= dgs->dgs_cbufsz;
		dg_sco_destroy(sco);
	}
}


static int
xp_dg_sco_reply(ar_svc_xprt_t *xp, ar_svc_call_obj_t sco)
{
	ar_ioep_t	ioep;
	dge_sco_t	*dgs;
	dg_ioep_t	*dep;
	struct sockaddr *sa;
	socklen_t	salen;
	axdr_ret_t	ret;
	axdr_state_t	xdr;
	char		*buf;
	int		len;
	int		err;
	struct timespec ts1;

	if (!xp || !sco) {
		return EINVAL;
	}

	ioep = xp->xp_ioep;
	if (!ioep) {
		dg_sco_destroy(sco);
		/* link went away before response.  Just cleanup */
		return 0;
	}

	dgs = (dge_sco_t *)sco->sco_lower;
	dep = (dg_ioep_t *)ioep->iep_drv_arg;

	assert(dgs != NULL && dep != NULL);

	assert(sco->sco_state == SCO_STATE_CALL);
	TAILQ_REMOVE(&ioep->iep_svc_async_calls, sco, sco_listent);

	sco->sco_state = SCO_STATE_SEND_REPLY;

	if (!dep->dep_caching) {
		/* caching disabled, just xmit response and we're done */
		TAILQ_INSERT_TAIL(&ioep->iep_svc_replies, sco, sco_listent);
		dg_sendmsg(ioep, &sco->sco_reply, sco);
		dg_sco_destroy(sco);
		return 0;
	}

	/* format response */
	axdrmem_create(&xdr, dep->dep_buf, dep->dep_bufsz, AXDR_ENCODE);
	ret = axdr_msg(&xdr, &sco->sco_reply);
	buf = dep->dep_buf;
	len = axdr_getpos(&xdr);
	axdr_destroy(&xdr);

	if (ret != AXDR_DONE) {
		TAILQ_INSERT_TAIL(&ioep->iep_svc_replies, sco, sco_listent);
		ar_svcerr_systemerr(xp, sco->sco_reply.arm_xid, sco);
		dg_sco_destroy(sco);
		return 0;
	}

	if (dgs->dgs_cbuf) {
		free(dgs->dgs_cbuf);
	}
	dgs->dgs_cbuf = malloc(len);
	if (!dgs->dgs_cbuf) {
		TAILQ_INSERT_TAIL(&ioep->iep_svc_replies, sco, sco_listent);
		ar_svcerr_systemerr(xp, sco->sco_reply.arm_xid, sco);
		dg_sco_destroy(sco);
		return 0;
	}
	memcpy(dgs->dgs_cbuf, buf, len);
	dgs->dgs_cbufsz = len;

	dg_cache_makeroom(ioep, len);

	if (dep->dep_connect) {
		sa = NULL;
		salen = 0;
	} else {
		sa = (struct sockaddr *)dgs->dgs_addr.buf;
		salen = dgs->dgs_addr.len;
	}
	
	err = sendto(dep->dep_fd, buf, len, 0, sa, salen);
	if (err < 0) {
		err = errno;
	} else {
		err = 0;
	}

	ar_gettime(&ts1);
	tspecadd(&ts1, &dep->dep_cache_time, &ts1);

	dgs->dgs_xid = sco->sco_reply.arm_xid;
	dgs->dgs_cache_timeout = ts1;

	sco->sco_state = SCO_STATE_CACHED;
	TAILQ_INSERT_TAIL(&ioep->iep_svc_cache, sco, sco_listent);

	return err;
}

static int
xp_dg_sco_alloc(ar_svc_xprt_t *xp, ar_svc_call_obj_t *scop)
{
	ar_svc_call_obj_t	sco;
	dge_sco_t	*dgs;
	int		len;
	int		err;

	if (!xp || !scop) {
		return EINVAL;
	}

	len = sizeof(*sco) + sizeof(*dgs);
	sco = malloc(len);
	if (!sco) {
		return ENOMEM;
	}

	memset(sco, 0, len);

	dgs = (dge_sco_t *)&sco[1];
	err = ar_svc_sco_init(sco, xp);
	if (err != 0) {
		free(sco);
		return err;
	}

	sco->sco_lower = dgs;

	/* bump xp ref so we don't loose our function handlers */
	dg_xp_bumpref(xp);
	
	*scop = sco;
	return 0;
}

static void
xp_dg_sco_destroy(ar_svc_xprt_t *xp, ar_svc_call_obj_t sco)
{
	if (!xp || !sco) {
		return;
	}

	dg_sco_bumpref(sco);

	if ((sco->sco_flags & SCO_FLG_USRREF_DEC) == 0) {
		sco->sco_flags |= SCO_FLG_USRREF_DEC;
		dg_sco_dropref(sco);
	}
	
	dg_sco_destroy(sco);
	dg_sco_dropref(sco);
}

static void
xp_dg_destroy(ar_svc_xprt_t *xp)
{
	if (!xp) {
		return;
	}

	dg_xp_bumpref(xp);

	if ((xp->xp_flags & XP_FLG_USRREF_DEC) == 0) {
		xp->xp_flags |= XP_FLG_USRREF_DEC;
		dg_xp_dropref(xp);
	}

	dg_xp_destroy(xp);
	dg_xp_dropref(xp);
}

static bool_t
xp_dg_control(ar_svc_xprt_t *xp, u_int cmd, void *info)
{
	arpc_addr_t *nb;
	ar_ioep_t ioep;
	dg_ioep_t *dep;
	int err;

	if (!xp) {
		return FALSE;
	}

	ioep = xp->xp_ioep;
	if (!ioep) {
		return FALSE;
	}

	dep = (dg_ioep_t *)ioep->iep_drv_arg;
	if (!dep) {
		return FALSE;
	}

	switch (cmd) {
	case AR_SVCGET_REMOTE_ADDR:
		if (!info) {
			return FALSE;
		}
		nb = (arpc_addr_t *)info;
		nb->len = nb->maxlen;
		/* because we're connectionless, first attempt to lookup
		 * the request from the currently active sco object.
		 */
		if (dep->dep_cur_addr) {
			if (dep->dep_cur_addr->len > nb->maxlen) {
				return FALSE;
			}
			memcpy(nb->buf, dep->dep_cur_addr->buf,
			       dep->dep_cur_addr->len);
			nb->len = dep->dep_cur_addr->len;
			return TRUE;
		}

		/* try for a connected dg socket's peer */
		err = getpeername(dep->dep_fd, (struct sockaddr *)nb->buf,
				  &nb->len);
		if (err < 0) {
			return FALSE;
		} else {
			return TRUE;
		}
	case AR_SVCGET_LOCAL_ADDR:
		if (!info) {
			return FALSE;
		}
		nb = (arpc_addr_t *)info;
		nb->len = nb->maxlen;
		err = getsockname(dep->dep_fd, (struct sockaddr *)nb->buf,
				  &nb->len);
		if (err < 0) {
			return FALSE;
		} else {
			return TRUE;
		}
	case AR_SVCGET_FD:
		*((int *)info) = dep->dep_fd;
		return TRUE;
	default:
		return ar_svc_control_default(xp, cmd, info);
	}
}


int
ar_svc_dg_create(ar_ioctx_t ctx, int fd, 
		 ar_svc_attr_t *attr, arpc_err_t *errp, ar_svc_xprt_t **retp)
{
	struct sockaddr_storage ss;
	int			sendsz;
	int			recvsz;
	ar_ioep_t		ioep;
	ar_svc_attr_t		lattr;
	dg_ioep_t		*dep;
	sa_family_t		family;
	int			err;
	socklen_t		slen;
	int			flags;

	if (!ctx || !retp || fd < 0) {
		err = EINVAL;
		goto error;
	}

	memset(&ss, 0, sizeof(ss));
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
	ss.ss_len = sizeof(ss);
#endif
	slen = sizeof(ss);
	err = getsockname(fd, (struct sockaddr *)&ss, &slen);
	if (err < 0) {
		err = errno;
		goto error;
	}
	family = ss.ss_family;

	/* always want nonblocking */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		err = errno;
		goto error;
	}
	flags |= O_NONBLOCK|O_NDELAY;
	err = fcntl(fd, F_SETFL, flags);
	if (err != 0) {
		err = errno;
		goto error;
	}

	/* close on exec */
	err = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (err != 0) {
		err = errno;
		goto error;
	}

	if (!attr) {
		err = ar_svc_attr_init(&lattr);
		if (err != 0) {
			goto error;
		}
		attr = &lattr;
	}

	sendsz = ar_get_t_size(family, IPPROTO_UDP, attr->sa_sendsz);
	recvsz = ar_get_t_size(family, IPPROTO_UDP, attr->sa_recvsz);

	/* create the ioep */
	err = io_dg_ep_create(ctx, sendsz, recvsz, NULL, attr, errp, &ioep);
	if (err != 0) {
		goto cleanup;
	}

	dep = (dg_ioep_t *)ioep->iep_drv_arg;

	/* setup fd */
	dep->dep_fd = fd;

	/* add ioep to ioctx */
	TAILQ_INSERT_TAIL(&ctx->icx_ep_list, ioep, iep_listent);

	err = vc_add_svc_ctx(ioep, attr);
	if (err != 0) {
		dg_ioep_destroy(ioep);
		goto error;
	}

	/* return xp */
	*retp = ioep->iep_svc_ctx;
	err = 0;
error:
	if (errp) {
		ar_errno2err(errp, err);
	}
cleanup:
	if (attr == &lattr) {
		ar_svc_attr_destroy(&lattr);
	}
	return err;
}
