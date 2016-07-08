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
 * Copyright (c) 1986-1996,1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "compat.h"

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>
#include <libarpc/stack.h>
#include <libarpc/arpc.h>
#include <libarpc/arpc_io.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "rpc_com.h"

#define CG_MIN_RPC_TIMEOUT_PERCONN_SECS     (15)
#define CG_MIN_RPC_TIMEOUT_PERCONN_NSECS    (0)

typedef struct clnt_gen_priv_s clnt_gen_priv_t;
typedef int (*clnt_gen_handler_t)(clnt_gen_priv_t *priv);

struct clnt_gen_priv_s {
	uint32_t		cg_flags;
	ar_ioctx_t		cg_ioctx;
	arpcb_client_t		cg_bind_client;
	ar_client_t		*cg_backptr;
	ar_client_t		*cg_running;
	clnt_gen_handler_t	cg_handler;
	astk_t			cg_stack;
	uint32_t		cg_stk_buf[32];
	ar_clnt_attr_t		cg_attrs;
	struct timespec		cg_tlimit;
	int			cg_ni_nlist;
	char			**cg_ni_list;
	char			*cg_host;
	char			*cg_netid;
	int			cg_active_ni;
	ar_auth_t		*cg_auth;
	arpc_addr_t		cg_addr;
	arpc_createerr_t	cg_err;
	struct ar_xid_state_s	cg_xid_state;
	arpcprog_t 		cg_prog;
	arpcvers_t		cg_ver;

	cco_list_t		cg_queued_calls;
};

#define CG_FLG_FINDADDR_DONE	0x00000001
#define CG_FLG_TLI_CREATE_DONE	0x00000002
#define CG_FLG_INCALL		0x00000004
#define CG_FLG_DONE		0x00000008

static int clnt_generic_call(ar_client_t *clnt, arpcproc_t proc, 
			     axdrproc_t xargs, void *argsp, bool_t inplace,
			     axdrproc_t xres, void *resp, int ressize,
			     ar_clnt_async_cb_t cb, void *cb_arg, 
			     struct timespec *tout, ar_clnt_call_obj_t *ccop);
static void clnt_generic_destroy(ar_client_t *clnt);
static bool_t clnt_generic_control(ar_client_t *clnt, u_int cmd, void *arg);
static int clnt_generic_handoff(ar_client_t *src, ar_client_t *dst,
				cco_list_t *msglist,
				struct ar_xid_state_s *xstate, 
				arpc_createerr_t *errp);
static int clnt_generic_cancel(ar_client_t *cl, ar_clnt_call_obj_t cco);
static void clnt_generic_reauth(ar_client_t *cl, ar_clnt_call_obj_t cco);
static void clnt_generic_dropref(ar_client_t *cl, ar_clnt_call_obj_t cco);
static void gen_priv_destroy(clnt_gen_priv_t *priv);

static struct clnt_ops clnt_generic_ops = {
	&clnt_generic_call,
	&clnt_generic_destroy,
	&clnt_generic_control,
	&clnt_generic_handoff,
	&clnt_generic_cancel,
	&clnt_generic_reauth,
	&clnt_generic_dropref
};

static void gen_clnt_destroy(ar_client_t *cl);
static void gen_cco_destroy(ar_clnt_call_obj_t cco);
static void gen_clnt_bumpref(ar_client_t *cl);
static void gen_clnt_dropref(ar_client_t *cl);
#if 0
static void gen_cco_bumpref(ar_clnt_call_obj_t cco);
#endif
static void gen_cco_dropref(ar_clnt_call_obj_t cco);

static void
gen_set_syserr(ar_clnt_call_obj_t cco, int err)
{
	cco->cco_rpc_err.re_status = ARPC_ERRNO;
	cco->cco_rpc_err.re_errno = err;
}


static void
gen_clnt_destroy(ar_client_t *cl)
{
	ar_clnt_call_obj_t	cco;
	clnt_gen_priv_t 	*priv;
	arpc_err_t		result;

	assert(cl != NULL);

	cl->cl_flags |= CLNT_FLG_DESTROY;
	cl->cl_refcnt++;	/* for safety */

	if (cl->cl_queued_err < 0) {
		/* set a generic error */
		cl->cl_queued_err = EIO;
	}

	memset(&result, 0, sizeof(result));
	if (cl->cl_queued_err < 0) {
		/* set a generic error */
		cl->cl_queued_err = EIO;
		result.re_status = ARPC_INTR;
	} else {
		ar_errno2err(&result, cl->cl_queued_err);
	}

	priv = (clnt_gen_priv_t *)cl->cl_private;
	while ((cco = TAILQ_FIRST(&priv->cg_queued_calls)) != NULL) {
		cco->cco_rpc_err = result;
		if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
			/* steal back usr reference, after notify */
			cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
			(*cco->cco_cb)(cco, cco->cco_cb_arg, &result, NULL);
			gen_cco_destroy(cco);
			/* actually drop usr ref */
			gen_cco_dropref(cco);	
		} else {
			/* can this happen? */
			gen_cco_destroy(cco);
		}
	}

	if (priv->cg_running) {
		ar_clnt_destroy(priv->cg_running);
		priv->cg_running = NULL;
	}
	cl->cl_refcnt--;
	if (cl->cl_refcnt <= 0) {
		gen_priv_destroy(priv);
		free(cl);
	}
}

static void
gen_cco_destroy(ar_clnt_call_obj_t cco)
{
	ar_client_t 		*cl;
	clnt_gen_priv_t *priv;

	assert(cco != NULL);
	cl = cco->cco_client;
	assert(cl != NULL);

	if (cco->cco_state != CCO_STATE_DEAD) {
		priv = (clnt_gen_priv_t *)cl->cl_private;
		assert(priv != NULL);
	} else {
		priv = NULL;
	}

	cco->cco_flags |= CCO_FLG_DESTROY;

	switch (cco->cco_state) {
	case CCO_STATE_QUEUED:
	case CCO_STATE_RESULTS:
	case CCO_STATE_DONE:
	case CCO_STATE_PENDING:
	case CCO_STATE_RUNNING:
		TAILQ_REMOVE(&priv->cg_queued_calls, cco, cco_listent);
		ar_clnt_cco_cleanup(priv->cg_auth, cco);
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
	gen_clnt_dropref(cl);
	
	free(cco);
}

static void
gen_clnt_bumpref(ar_client_t *cl)
{
	assert(cl != NULL);
	cl->cl_refcnt++;
}

static void
gen_clnt_dropref(ar_client_t *cl)
{
	assert(cl != NULL);
	cl->cl_refcnt--;
	if (cl->cl_refcnt <= 0  &&
	    (cl->cl_flags & CLNT_FLG_DESTROY) != 0) {
		gen_clnt_destroy(cl);
	}
}

#if 0
static void
gen_cco_bumpref(ar_clnt_call_obj_t cco)
{
	assert(cco != NULL);
	cco->cco_refcnt++;
}
#endif

static void
gen_cco_dropref(ar_clnt_call_obj_t cco)
{
	assert(cco != NULL);
	cco->cco_refcnt--;
	if (cco->cco_refcnt <= 0 &&
	    (cco->cco_flags & CCO_FLG_DESTROY) != 0) {
		gen_cco_destroy(cco);
	}
}

static int
clnt_generic_call(ar_client_t *cl, arpcproc_t proc, axdrproc_t xargs, 
		  void *argsp, bool_t inplace, axdrproc_t xres, void *resp,
		  int ressize, ar_clnt_async_cb_t cb, void *cb_arg,
		  struct timespec *tout, ar_clnt_call_obj_t *ccop)
{
	ar_clnt_call_obj_t cco;
	clnt_gen_priv_t *priv;
	int		err;

	if (!cl || !xargs || !cb || !ccop) {
		return EINVAL;
	}

	if (cl->cl_queued_err > 0) {
		return cl->cl_queued_err;
	}

	priv = (clnt_gen_priv_t *)cl->cl_private;
	assert(priv != NULL);

	if ((priv->cg_flags & CG_FLG_DONE) != 0) {
		/* attempt to resolve/connect failed.  return error */
		return ENOTCONN;
	}

	cco = malloc(sizeof(*cco));
	if (!cco) {
		return ENOMEM;
	}
	memset(cco, 0, sizeof(*cco));

	err = ar_clnt_cco_init(cco, cl, priv->cg_auth, &priv->cg_xid_state,
			       proc, xargs, argsp, inplace, xres, 
			       resp, ressize, cb, cb_arg, tout);
	if (err != 0) {
		free(cco);
		return err;
	}

	cco->cco_state = CCO_STATE_QUEUED;

	/* bump client reference for ref from cco */
	gen_clnt_bumpref(cl);

	TAILQ_INSERT_TAIL(&priv->cg_queued_calls, cco, cco_listent);

	*ccop = cco;
	return 0;
}

static void
clnt_generic_dropref(ar_client_t *cl, ar_clnt_call_obj_t cco)
{
	gen_cco_dropref(cco);
	return;
}

static void
clnt_generic_reauth(ar_client_t *cl, ar_clnt_call_obj_t cco)
{
	return;
}

static int
clnt_generic_cancel(ar_client_t *cl, ar_clnt_call_obj_t cco)
{
	if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
		cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
		gen_cco_destroy(cco);
		gen_cco_dropref(cco);
	} else {
		gen_cco_destroy(cco);
	}
	return 0;
}


static void
clnt_generic_destroy(ar_client_t *cl)
{
	if (!cl) {
		return;
	}

	gen_clnt_bumpref(cl);

	if ((cl->cl_flags & CLNT_FLG_USRREF_DEC) == 0) {
		cl->cl_flags |= CLNT_FLG_USRREF_DEC;
		gen_clnt_dropref(cl);
	}

	gen_clnt_destroy(cl);
	gen_clnt_dropref(cl);
}

static bool_t
clnt_generic_control(ar_client_t *clnt, u_int cmd, void *arg)
{
	return FALSE;
}


static int
clnt_generic_handoff(ar_client_t *src, ar_client_t *dst, cco_list_t *msglist, 
		     struct ar_xid_state_s *xstate, arpc_createerr_t *errp)
{
	return EINVAL;
}


static int
gen_priv_create(ar_ioctx_t ioctx, ar_clnt_attr_t *attrs,
		clnt_gen_priv_t **privp)
{
	clnt_gen_priv_t *priv;
	struct timespec ts;
	uint8_t *ptr;
	int err;

	if (!privp) {
		return EINVAL;
	}

	priv = malloc(sizeof(*priv));
	if (!priv) {
		return ENOMEM;
	}
	memset(priv, 0, sizeof(*priv));

	priv->cg_ioctx = ioctx;
	ar_xid_init(&priv->cg_xid_state);

	if (attrs) {
		/* NOTE: if there is ever dynamic stuff hanging off of
		 * attr, we'll have to deal with that here.
		 */
		memcpy(&priv->cg_attrs, attrs, sizeof(priv->cg_attrs));
		if (attrs->ca_pkcs12) {
			ptr = (uint8_t *)malloc(attrs->ca_pkcs12_len);
			if (!ptr) {
				free(priv);
				return ENOMEM;
			}
			priv->cg_attrs.ca_pkcs12 = ptr;
			memcpy(ptr, attrs->ca_pkcs12, attrs->ca_pkcs12_len);
		}
	} else {
		err = ar_clnt_attr_init(&priv->cg_attrs);
		if (err != 0) {
			free(priv);
			return 0;
		}
	}

	ar_gettime(&ts);
	tspecadd(&ts, &priv->cg_attrs.ca_create_tmout, &priv->cg_tlimit);

	err = astk_init(&priv->cg_stack);
	if (err != 0) {
		if (priv->cg_attrs.ca_pkcs12) {
			free(priv->cg_attrs.ca_pkcs12);
			priv->cg_attrs.ca_pkcs12 = NULL;
		}
		free(priv);
		return err;
	}

	priv->cg_auth = ar_authnone_create();
	if (!priv->cg_auth) {
		astk_cleanup(&priv->cg_stack);
		if (priv->cg_attrs.ca_pkcs12) {
			free(priv->cg_attrs.ca_pkcs12);
			priv->cg_attrs.ca_pkcs12 = NULL;
		}
		
		free(priv);
		return ENOMEM;
	}

#if 0
	/* FIXME */
	err = astk_set_buf(&priv->cg_stack, priv->cg_stk_buf, 
				sizeof(priv->cg_stk_buf), FALSE);
	if (err != 0) {
		auth_destroy(priv->cg_auth);
		priv->cg_auth = NULL;
		astk_cleanup(&priv->cg_stack);
		free(priv);
		return err;
	}
#endif
	TAILQ_INIT(&priv->cg_queued_calls);

	*privp = priv;
	return 0;
}

static void
gen_priv_destroy(clnt_gen_priv_t *priv)
{
	ar_clnt_call_obj_t	cco;
	int 			i;
	arpc_err_t		err;

	if (!priv) {
		return;
	}

	ar_auth_destroy(priv->cg_auth);
	priv->cg_auth = NULL;

	astk_cleanup(&priv->cg_stack);

	for (i = 0; i < priv->cg_ni_nlist; i++) {
		free(priv->cg_ni_list[i]);
		priv->cg_ni_list[i] = NULL;
	}

	if (priv->cg_ni_list) {
		free(priv->cg_ni_list);
	}
	priv->cg_ni_list = NULL;
	if (priv->cg_host) {
		free(priv->cg_host);
	}
	priv->cg_host = NULL;

	if (priv->cg_netid) {
		free(priv->cg_netid);
	}
	priv->cg_netid = NULL;

	if (priv->cg_addr.buf) {
		free(priv->cg_addr.buf);
	}
	priv->cg_addr.buf = NULL;
	priv->cg_addr.len = 0;
	priv->cg_addr.maxlen = 0;

	if (priv->cg_attrs.ca_pkcs12) {
		free(priv->cg_attrs.ca_pkcs12);
		priv->cg_attrs.ca_pkcs12 = NULL;
	}
	if (priv->cg_bind_client) {
		arpcb_clnt_destroy(priv->cg_bind_client);
		priv->cg_bind_client = NULL;
	}

	/* free any pending clients */
	while ((cco = TAILQ_FIRST(&priv->cg_queued_calls)) != NULL) {
		if ((cco->cco_flags & CCO_FLG_USRREF_DROPPED) == 0) {
			/* steal back usr reference, after notify */
			cco->cco_flags |= CCO_FLG_USRREF_DROPPED;
			cco->cco_rpc_err.re_status = ARPC_INTR;
			err = cco->cco_rpc_err;

			(*cco->cco_cb)(cco, cco->cco_cb_arg, &err, NULL);
			gen_cco_destroy(cco);
			/* actually drop usr ref */
			gen_cco_dropref(cco);	
		} else {
			/* can this happen? */
			gen_cco_destroy(cco);
		}
	}

	free(priv);
}

static int
gen_priv_set_netid(clnt_gen_priv_t *priv, const char *netid, 
		   arpc_createerr_t *cferr)
{
	ar_netid_t *info;
	char **nilist;
	char *cp;
	int nsize;
	int err;
	int i;

	cferr->cf_stat = ARPC_SUCCESS;

	if (!priv) {
		err = EINVAL;	
		goto error;
	}

	if (priv->cg_netid) {
		free(priv->cg_netid);
	}
	priv->cg_netid = NULL;
	if (netid) {
		err = ar_str2netid(priv->cg_ioctx, netid, &info);
		if (err != EOK) {
			cferr->cf_stat = ARPC_UNKNOWNPROTO;
			cferr->cf_error.re_status = ARPC_UNKNOWNPROTO;
			return EPROTO;
		}
		priv->cg_netid = strdup(netid);
		if (!priv->cg_netid) {
			err = ENOMEM;
			goto error;
		}
		nilist = malloc(sizeof(char *));
		if (!nilist) {
			err = ENOMEM;
			goto error;
		}
		nilist[0] = strdup(netid);
		if (!nilist[0]) {
			free(nilist);
			err = ENOMEM;
			goto error;
		}
		if (priv->cg_ni_list) {
			for (i = 0; i < priv->cg_ni_nlist; i++) {
				free(priv->cg_ni_list[i]);
				priv->cg_ni_list[i] = NULL;
			}
			free(priv->cg_ni_list);
		}
		priv->cg_ni_list = nilist;
		priv->cg_ni_nlist = 1;
		return 0;
	}

	for (i = 0; ; i++) {
		err = ar_idx2netid(priv->cg_ioctx, i, &info);
		if (err != EOK) {
			goto error;
		}
		if (!info) {
			/* end of list */
			break;
		}

		nsize = sizeof(char *) * (priv->cg_ni_nlist + 1);
		nilist = realloc(priv->cg_ni_list, nsize);
		if (!nilist) {
			err = ENOMEM;
			goto error;
		}
		priv->cg_ni_list = nilist;
		cp = strdup(info->an_netid);
		priv->cg_ni_list[priv->cg_ni_nlist] = cp;
		if (!cp) {
			err = ENOMEM;
			goto error;
		}
		priv->cg_ni_nlist++;
	}

	if (priv->cg_ni_nlist <= 0) {
		if (cferr->cf_stat == ARPC_SUCCESS) { 
			cferr->cf_stat = ARPC_UNKNOWNPROTO;
			cferr->cf_error.re_status = ARPC_UNKNOWNPROTO;
		}
		return EPROTO;
	}

	return 0;

error:		
	cferr->cf_stat = ARPC_ERRNO;
	cferr->cf_error.re_status = ARPC_ERRNO;
	cferr->cf_error.re_errno = err;
	return err;
}

static int
gen_priv_set_hostname(clnt_gen_priv_t *priv, const char *host,
		      arpc_createerr_t *cferr)
{
	int err;

	if (!priv || !host) {
		err = EINVAL;
		goto error;
	}

	priv->cg_host = strdup(host);
	if (!priv->cg_host) {
		err = ENOMEM;
		goto error;
	}

	return 0;

error:
	cferr->cf_stat = ARPC_ERRNO;
	cferr->cf_error.re_status = ARPC_ERRNO;
	cferr->cf_error.re_errno = err;
	return err;
}

static int
gen_create(ar_client_t **retp)
{
	ar_client_t *clnt;

	if (!retp) {
		return EINVAL;
	}

	clnt = malloc(sizeof(*clnt));
	if (!clnt) {
		return ENOMEM;
	}

	memset(clnt, 0, sizeof(*clnt));

	clnt->cl_refcnt = 1;	/* 1 ref form user */
	clnt->cl_ops = &clnt_generic_ops;
	clnt->cl_defwait.tv_sec = CG_DEF_RPC_TIMEOUT_SECS;
	clnt->cl_defwait.tv_nsec = CG_DEF_RPC_TIMEOUT_NSECS;
	clnt->cl_queued_err = -1;

	*retp = clnt;
	return 0;
}

static void
gen_io_handle_complete(clnt_gen_priv_t *priv, int err)
{
	ar_client_t		*cl;
	ar_clnt_call_obj_t	cco;
	void			*private;
	clnt_handoff_t		hoff;
	int			count;
	int			cnt2;

	cl = priv->cg_backptr;

	gen_clnt_bumpref(cl);
	priv->cg_flags |= CG_FLG_DONE;

	if (err == 0) {
		/* disconnect */
		cl->cl_private = NULL;
		cl->cl_ops = NULL;
		cl->cl_ioep = NULL;

		/* We have a connected client in cg_running. Need
		 * to link it to cg_backptr client since that's the
		 * handle the user has.  This should just queue the
		 * requests, not actually trigger any io.  We should rely
		 * on a poll out to do that
		 */
		hoff = priv->cg_running->cl_ops->cl_handoff;
		count = 0;
		TAILQ_FOREACH(cco, &priv->cg_queued_calls, cco_listent) {
			count++;
		}
		/* our cco's have references to the client.  Release those
		 * before the handoff.
		 */
		cl->cl_refcnt -= count;
		err = (*hoff)(priv->cg_running, cl, &priv->cg_queued_calls,
			      &priv->cg_xid_state, &priv->cg_err);
		if (err == EAGAIN) {
			err = EIO;
		}
		if (err == 0) {
			assert(TAILQ_EMPTY(&priv->cg_queued_calls));
			priv->cg_running = NULL;/* free'd by handoff */
			priv->cg_backptr = NULL;
		} else {
			/* have to restore these so basic destroy
			 * functions work...
			 */
			cnt2 = 0;
			TAILQ_FOREACH(cco, &priv->cg_queued_calls, 
				      cco_listent) {
				cnt2++;
			}

			cl->cl_private = priv;
			cl->cl_ops = &clnt_generic_ops;
			assert(cnt2 == count);
			cl->cl_refcnt += count;
		}
	}

	if (err != 0) {
		if (priv->cg_err.cf_stat == ARPC_SUCCESS) {
			priv->cg_err.cf_stat = ARPC_ERRNO;
			priv->cg_err.cf_error.re_status = ARPC_ERRNO;
			priv->cg_err.cf_error.re_errno = err;
		}
		cl->cl_queued_err = err;
	}

	if (err == 0) {
		/* decrement our reference up front.  We don't want
		 * to handle a destroy queued by the handed off client
		 * queued from the conn callback.
		 */
		cl->cl_refcnt--;
	}
	private = cl->cl_private;

	if (priv->cg_attrs.ca_conn_cb) {
		(*priv->cg_attrs.ca_conn_cb)(cl, priv->cg_attrs.ca_conn_arg,
					     &priv->cg_err);
	}

	/* Clean up the private structure if required.
	 */
	if (private != priv) {
		gen_priv_destroy(priv);
	}

	if (err != 0) {
		gen_clnt_destroy(cl);
		gen_clnt_dropref(cl);
	}
}

static void
gen_io_tp_findaddr_done(arpcb_client_t rpcb, void *arg, 
			arpc_createerr_t *errp, const arpc_addr_t *addr)
{
	clnt_gen_priv_t *priv;
	int err;

	priv = (clnt_gen_priv_t *)arg;
	assert(priv != NULL);
	assert(errp != NULL);
	assert(rpcb == priv->cg_bind_client);

	/* bind context goes away after callback, clear reference */
	priv->cg_bind_client = NULL;

	memcpy(&priv->cg_err, errp, sizeof(priv->cg_err));
	if (addr && errp->cf_stat == ARPC_SUCCESS) {
		if (priv->cg_addr.buf) {
			free(priv->cg_addr.buf);
			priv->cg_addr.buf = NULL;
			priv->cg_addr.len = 0;
			priv->cg_addr.maxlen = 0;
		}
		priv->cg_addr.buf = malloc(addr->maxlen);
		if (!priv->cg_addr.buf) {
			priv->cg_err.cf_stat = ARPC_ERRNO;
			priv->cg_err.cf_error.re_status = ARPC_ERRNO;
			priv->cg_err.cf_error.re_errno = ENOMEM;
		} else {
			memcpy(priv->cg_addr.buf, addr->buf, addr->len);
			priv->cg_addr.len = addr->len;
			priv->cg_addr.maxlen = addr->maxlen;
		}
	} else if (errp->cf_stat == ARPC_SUCCESS) {
		priv->cg_err.cf_stat = ARPC_N2AXLATEFAILURE;
		priv->cg_err.cf_error.re_status = ARPC_N2AXLATEFAILURE;
	}

	priv->cg_flags |= CG_FLG_FINDADDR_DONE;

	if (priv->cg_flags & CG_FLG_INCALL) {
		/* recursive, skip handler calls */
		return;
	}

	err = (*priv->cg_handler)(priv);
	if (err != EAGAIN) {
		gen_io_handle_complete(priv, err);
	}
}


static void
gen_io_tli_done(ar_client_t *clnt, void *arg, const arpc_createerr_t *errp)
{
	clnt_gen_priv_t *priv;
	int err;

	assert(clnt != NULL);
	assert(arg != NULL);
	assert(errp != NULL);

	priv = (clnt_gen_priv_t *)arg;
	priv->cg_flags |= CG_FLG_TLI_CREATE_DONE;
	memcpy(&priv->cg_err, errp, sizeof(priv->cg_err));
	
	if (priv->cg_flags & CG_FLG_INCALL) {
		/* recursive, skip handler calls */
		return;
	}

	err = (*priv->cg_handler)(priv);
	if (err != EAGAIN) {
		gen_io_handle_complete(priv, err);
	}
}


static int
gen_io_tp_create_dispatch(clnt_gen_priv_t *priv)
{
	int			state;
	int			err;
	struct timespec		ts1;
	struct timespec		ts2;
	struct timespec		tszero;
	double			dval;
	const char		*netid;
	int			jobs;
	ar_clnt_attr_t		attr;
	ar_stat_t		stat;


	err = astk_enter(&priv->cg_stack, &gen_io_tp_create_dispatch,
			      &state, 0, NULL, 0);
	if (err != 0) {
		return err;
	}

	stat = priv->cg_err.cf_stat;

	if (!priv->cg_ni_list || priv->cg_active_ni >= priv->cg_ni_nlist) {
		stat = ARPC_UNKNOWNPROTO;
		err = EINVAL;
		goto cleanup;
	}			
	netid = priv->cg_ni_list[priv->cg_active_ni];

	switch (state) {
	case 0:
		ar_gettime(&ts1);
		tspecsub(&priv->cg_tlimit, &ts1, &ts1);
		tspecclear(&tszero);

		jobs = 3 * priv->cg_ni_nlist;
		ts2.tv_sec = ts1.tv_sec / jobs;
		dval = (double)(ts1.tv_sec % jobs);
		dval /= (double)jobs;
		ts2.tv_nsec = (int)(1000000000.0 * dval) + ts1.tv_nsec / jobs;
		tspecadd(&ts2, &tszero, &ts2);

		/* 2/3 of our proto's work is alloted to the bind lookup
		 * (1 RTT for resolve, 1 for lookup)
		 */
		ts2.tv_sec *= 2;
		ts2.tv_nsec *= 2;
		tspecadd(&ts2, &tszero, &ts2); /* normalize */
		
		if (tspeccmp(&ts2, &tszero, <=)) {
			stat = ARPC_TIMEDOUT;
			err = ETIMEDOUT;
			goto cleanup;
		}

		assert(priv->cg_bind_client == NULL);
		/*
		 * This is not the best fix but should work for now
		 * The problem with using the current scheme is timeout can get
		 * pretty small and session may not finish within this time
		 * frame in a busy system
		 * The real solution is to launch all the connections in
		 * parallel with the default timeout but maintain an order
		 * of prefernece, inspect the completions after the timeout
		 * period and use the result from most preferred connection.
		 */
		if (ts2.tv_sec < CG_MIN_RPC_TIMEOUT_PERCONN_SECS) {
			ts2.tv_sec = CG_MIN_RPC_TIMEOUT_PERCONN_SECS;
			ts2.tv_nsec = CG_MIN_RPC_TIMEOUT_PERCONN_NSECS;
		}
		/* resolve the server port/address
		 */
		priv->cg_flags &= ~CG_FLG_FINDADDR_DONE;
		priv->cg_flags |= CG_FLG_INCALL;
		state = 1;
		err = arpcb_findaddr_create(priv->cg_ioctx, priv->cg_prog,
					    priv->cg_ver, netid,
					    priv->cg_host, 
					    gen_io_tp_findaddr_done,
					    priv, &ts2, &priv->cg_err,
					    &priv->cg_bind_client);
		priv->cg_flags &= ~CG_FLG_INCALL;
		/* want to keep any updated error status */
		stat = priv->cg_err.cf_stat;
		if (err != 0) {
			if (err == EAGAIN) {
				err = EIO;
			}
			break;
		}
		/* fallthrough */
	case 1:
		if ((priv->cg_flags & CG_FLG_FINDADDR_DONE) == 0) {
			/* not done yet */
			err = EAGAIN;
			break;
		}

		if (priv->cg_err.cf_stat != ARPC_SUCCESS) {
			err = EIO;
			break;
		}
		state = 2;
		/* fallthrough */
	case 2:
		memcpy(&attr, &priv->cg_attrs, sizeof(attr));

		attr.ca_conn_cb = gen_io_tli_done;
		attr.ca_conn_arg = priv;

		/* compute correct partial timeout */
		ar_gettime(&ts1);
		tspecsub(&priv->cg_tlimit, &ts1, &ts1);
		tspecclear(&tszero);

		jobs = 3 * priv->cg_ni_nlist - 2;
		ts2.tv_sec = ts1.tv_sec / jobs;
		dval = (double)(ts1.tv_sec % jobs);
		dval /= (double)jobs;
		ts2.tv_nsec = (int)(1000000000.0 * dval) + ts1.tv_nsec / jobs;
		tspecadd(&ts2, &tszero, &ts2);

                /*
                 * workaround for small timeout issue, check the comments
                 * above (switch 0 )
                 */
                if (ts2.tv_sec < CG_MIN_RPC_TIMEOUT_PERCONN_SECS) {
                    ts2.tv_sec = CG_MIN_RPC_TIMEOUT_PERCONN_SECS;
                    ts2.tv_nsec = CG_MIN_RPC_TIMEOUT_PERCONN_NSECS;
                }
		attr.ca_create_tmout = ts2;

		assert(priv->cg_running == NULL);

		priv->cg_flags &= ~CG_FLG_TLI_CREATE_DONE;
		priv->cg_flags |= CG_FLG_INCALL;
		state = 3;
		err = ar_clnt_tli_create(priv->cg_ioctx, netid, &priv->cg_addr,
					 priv->cg_prog, priv->cg_ver, &attr,
					 &priv->cg_err, &priv->cg_running);
		priv->cg_flags &= ~CG_FLG_INCALL;
		/* want to keep any updated error status */
		stat = priv->cg_err.cf_stat;

		if (err != 0) {
			if (err == EAGAIN) {
				err = EIO;
			}
			break;
		}
		/* fallthrough */
	case 3:
		if ((priv->cg_flags & CG_FLG_TLI_CREATE_DONE) == 0) {
			/* not done yet */
			err = EAGAIN;
			break;
		}

		if (priv->cg_err.cf_stat != ARPC_SUCCESS) {
			err = EIO;
			break;
		} else {
			err = 0;
		}
		state = 4;
		break;
	default:
		err = EINVAL;
		stat = ARPC_ERRNO;
		break;
	}

 cleanup:
	if (err != EAGAIN && err != 0) {
		/* clean up all local state.  Global state cleanup is handled
		 * at the top layer (so if the completion callback 
		 * frees the client structure, everything works correctly.
		 */
		if (priv->cg_running) {
			ar_clnt_destroy(priv->cg_running);
			priv->cg_running = NULL;
		}
		if (priv->cg_addr.buf) {
			free(priv->cg_addr.buf);
		}
		priv->cg_addr.buf = NULL;
		priv->cg_addr.len = 0;
		priv->cg_addr.maxlen = 0;
	}

	if (stat != priv->cg_err.cf_stat) {
		priv->cg_err.cf_stat = stat;
		priv->cg_err.cf_error.re_status = stat;
		if (stat == ARPC_ERRNO) {
			priv->cg_err.cf_error.re_errno = err;
		}
	}

	astk_leave(&priv->cg_stack, &gen_io_tp_create_dispatch, state,
			err == EAGAIN);

	return err;
}


static int
gen_io_create_dispatch(clnt_gen_priv_t *priv)
{
	arpc_createerr_t	*saveerr;
	int			state;
	int			err;

	err = astk_enter(&priv->cg_stack, &gen_io_create_dispatch,
			      &state, 0, (void **)&saveerr,
			      sizeof(arpc_createerr_t));
	if (err != 0) {
		return err;
	}

	if (state == 0) {
		saveerr->cf_stat = ARPC_SUCCESS;
		saveerr->cf_error.re_status = ARPC_SUCCESS;
	}

	for (; state < priv->cg_ni_nlist; state++) {
		priv->cg_active_ni = state;
		err = gen_io_tp_create_dispatch(priv);
		if (err == 0 || err == EAGAIN) {
			break;
		}

		/* try the next transport */
		/*
		 *	Since we didn't get a name-to-address
		 *	translation failure here, we remember
		 *	this particular error.  The object of
		 *	this is to enable us to return to the
		 *	caller a more-specific error than the
		 *	unhelpful ``Name to address translation
		 *	failed'' which might well occur if we
		 *	merely returned the last error (because
		 *	the local loopbacks are typically the
		 *	last ones in /etc/netconfig and the most
		 *	likely to be unable to translate a host
		 *	name).  We also check for a more
		 *	meaningful error than ``unknown host
		 *	name'' for the same reasons.
		 */
		if (priv->cg_err.cf_stat != ARPC_N2AXLATEFAILURE &&
		    priv->cg_err.cf_stat != ARPC_UNKNOWNHOST) {
			memcpy(saveerr, &priv->cg_err, sizeof(*saveerr));
		}
		memset(&priv->cg_err, 0, sizeof(priv->cg_err));
		priv->cg_err.cf_stat = ARPC_SUCCESS;
		priv->cg_err.cf_error.re_status = ARPC_SUCCESS;
	}

	if (state < 0 || state >= priv->cg_ni_nlist) {
		/* beyond limits */
		if (saveerr->cf_stat != ARPC_SUCCESS) {
			memcpy(&priv->cg_err, saveerr, sizeof(priv->cg_err));
		}
		err = EHOSTUNREACH;
	}

	astk_leave(&priv->cg_stack, &gen_io_create_dispatch, state,
		   err == EAGAIN);

	return err;
}

int
ar_clnt_create(ar_ioctx_t ioctx, const char *host, const arpcprog_t prog,
	       const arpcvers_t ver, const char *netid, ar_clnt_attr_t *attr,
	       arpc_createerr_t *errp, ar_client_t **retp)
{
	clnt_gen_priv_t *priv = NULL;
	ar_client_t *cl = NULL;
	int err;

	RPCTRACE(ioctx, 2,
		 "ar_clnt_create(): netid %s, prog %x, ver %x\n",
		 netid, prog, ver);
	
	if (!ioctx || !host || !retp) {
		if (errp) {
			errp->cf_stat = ARPC_ERRNO;
			errp->cf_error.re_status = ARPC_ERRNO;
			errp->cf_error.re_errno = EINVAL;
		}
		return EINVAL;
	}

	err = gen_priv_create(ioctx, attr, &priv);
	if (err != 0) {
		if (errp) {
			errp->cf_stat = ARPC_ERRNO;
			errp->cf_error.re_status = ARPC_ERRNO;
			errp->cf_error.re_errno = err;
		}
		return err;
	}

	err = gen_priv_set_netid(priv, netid, &priv->cg_err);
	if (err != EOK) {
		goto error;
	}

	err = gen_priv_set_hostname(priv, host, &priv->cg_err);
	if (err != 0) {
		goto error;
	}

	err = gen_create(&cl);
	if (err != 0) {
		priv->cg_err.cf_stat = ARPC_ERRNO;
		priv->cg_err.cf_error.re_status = ARPC_ERRNO;
		priv->cg_err.cf_error.re_errno = err;
		goto error;
	}

	priv->cg_prog = prog;
	priv->cg_ver = ver;

	/* no ioep for generic pre-resolve client */
	cl->cl_ioctx = ioctx;
	cl->cl_prog = prog;
	cl->cl_ver = ver;
	cl->cl_private = priv;

	priv->cg_backptr = cl;
	
	*retp = cl;
	priv->cg_handler = &gen_io_create_dispatch;
	err = gen_io_create_dispatch(priv);
	if (err != EAGAIN) {
		gen_io_handle_complete(priv, err);
	}
	return 0;
 error:	
	if (errp) {
		memcpy(errp, &priv->cg_err, sizeof(priv->cg_err));
	}

	if (!cl) {
		gen_priv_destroy(priv);
	} else {
		ar_clnt_destroy(cl);
	}
	return err;
}

/*
 * Generic client creation:  returns client handle.
 * Default options are set, which the user can
 * change using the rpc equivalent of _ioctl()'s : clnt_control().
 * If fd is RPC_ANYFD, it will be opened using nconf.
 * It will be bound if not so.
 * If sizes are 0; appropriate defaults will be chosen.
 */
int 
ar_clnt_tli_create(ar_ioctx_t ioctx, const char *netid,
		   const arpc_addr_t *svcaddr, const arpcprog_t prog, 
		   const arpcvers_t ver, ar_clnt_attr_t *attr, 
		   arpc_createerr_t *errp, ar_client_t **retp)
{
	ar_vcd_t drv;
	int err;
	ar_stat_t stat;
	ar_sockinfo_t si;
	ar_netid_t *info;

	RPCTRACE(ioctx, 2,
		 "ar_clnt_tli_create(): netid %s, prog %x, ver %x\n",
		 netid, prog, ver);
	
	stat = ARPC_SUCCESS;

	if (!svcaddr || !retp || !ioctx) {
		stat = ARPC_ERRNO;
		err = EINVAL;
		goto error;
	}

	if (netid == NULL) {
		stat = ARPC_UNKNOWNPROTO;
		err = EINVAL;
		goto error;
	}

	err  = ar_str2sockinfo(ioctx, netid, &si);
	err |= ar_str2netid(ioctx, netid, &info);
	if (err != EOK) {
		stat = ARPC_UNKNOWNPROTO;
		err = EINVAL;
		goto error;
	}

	if (si.si_af != ((struct sockaddr *)svcaddr->buf)->sa_family) {
		stat = ARPC_UNKNOWNHOST;
		err = EINVAL;
		goto error;
	}

	switch (info->an_semantics) {
	case AR_SEM_COTS:
		err = ar_vcd_lookup(ioctx, netid, &drv);
		 if (err != 0) {
			stat = ARPC_UNKNOWNPROTO;
			goto error;
		}
		return ar_clnt_vc_create(ioctx, drv, svcaddr, prog, ver, 
					 attr, errp, retp);
	case AR_SEM_CLTS:
		return ar_clnt_dg_create(ioctx, svcaddr, prog, 
					 ver, attr, errp, retp);
	default:
		stat = ARPC_UNKNOWNPROTO;
		err = EINVAL;
		break;
	}

error:
	if (errp) {
		errp->cf_stat = stat;
		errp->cf_error.re_status = stat;
		if (stat == ARPC_ERRNO) {
			errp->cf_error.re_errno = err;
		}
	}
	return err;
}

axdr_ret_t
ar_clnt_handle_reply(axdr_state_t *xdrs, ar_ioep_t ioep, arpc_msg_t *msg,
		     ar_clnt_call_obj_t *ccop)
{
	axdr_ret_t rval;
	ar_clnt_call_obj_t cco;
	cco_state_t state;
	ar_client_t *cl;
	arpc_err_t *errp;
	ar_opaque_auth_t *auth;

	if (!xdrs || !ioep || !msg || !ccop) {
		return AXDR_ERROR;
	}
	*ccop = NULL;

	cco = ioep->iep_clnt_reply;
	if (!cco) {
		TAILQ_FOREACH(cco, &ioep->iep_clnt_calls, cco_listent) {
			if (cco->cco_xid == msg->arm_xid) {
				break;
			}
		}
		if (!cco) {
			/* no such object.  Just skip the 
			 * record (say we're done) 
			 */
			return AXDR_DONE;
		}

		if (cco->cco_state != CCO_STATE_PENDING &&
		    cco->cco_state != CCO_STATE_RUNNING) {
			/* what the heck... */
			ar_ioep_fatal_error(ioep);
			return AXDR_ERROR;
		}

		cl = cco->cco_client;
		assert(cl != NULL);

		ioep->iep_clnt_reply = cco;
		cco->cco_state = CCO_STATE_RESULTS;

		/* decode error and assocaite with call */
		errp = &cco->cco_rpc_err;
		if (msg->arm_reply.arp_stat == AR_MSG_ACCEPTED &&
		    msg->arm_acpted_rply.aar_stat == AR_SUCCESS) {
			errp->re_status = ARPC_SUCCESS;
		} else {
			ar_seterr_reply(msg, errp);
		}

		if (errp->re_status == ARPC_SUCCESS) {
			auth = &msg->arm_acpted_rply.aar_verf;
			if (!AR_AUTH_VALIDATE(ioep->iep_auth, auth)) {
				errp->re_status = ARPC_AUTHERROR;
				errp->re_why = AR_AUTH_INVALIDRESP;
				cco->cco_state = CCO_STATE_DONE;
			}
			if (msg->arm_acpted_rply.aar_verf.oa_base != NULL) {
				axdr_free((axdrproc_t)axdr_opaque_auth, 
					  &(msg->arm_acpted_rply.aar_verf));
			}
		} else if (errp->re_status == ARPC_AUTHERROR && 
			   cco->cco_authrefresh > 0 &&
			   AR_AUTH_REFRESH(ioep->iep_auth, msg)) {
			ioep->iep_clnt_reply = NULL;
			cco->cco_authrefresh--;
			cl->cl_ops->cl_reauth(cl, cco);
			return AXDR_DONE;
		} else {
			cco->cco_state = CCO_STATE_DONE;
		}
	}

	rval = AXDR_DONE;
	switch (cco->cco_state) {
	case CCO_STATE_RESULTS:
		if (!cco->cco_resp) {
			cco->cco_resp = malloc(cco->cco_ressize);
			if (!cco->cco_resp) {
				gen_set_syserr(cco, ENOMEM);
				*ccop = cco;
				return AXDR_ERROR;
			}
			memset(cco->cco_resp, 0, cco->cco_ressize);
			cco->cco_flags |= CCO_FLG_RESULT_ALLOCED;
		}
		errp = &cco->cco_rpc_err;
		/* NOTE: all sorts of cleanup can result due to io errors
		 * encountered in the io layers underlying the xdr object.
		 * We grab a reference to our cco here so we can have a valid
		 * pointer reference and determine what has happened if 
		 * the connection goes away.
		 */
		cco->cco_refcnt++;
		rval = (*cco->cco_xres)(xdrs, cco->cco_resp);
		state = cco->cco_state;
		cl = cco->cco_client;
		assert(cl != NULL);
		(*cl->cl_ops->cl_dropref)(cl, cco);
		if (state == CCO_STATE_DEAD) {
			/* underlying io layer has cleanup up object, bail
			 * out.
			 */
			return AXDR_ERROR;
		}
		if (rval == AXDR_WAITING) {
			return rval;
		}
		if (rval == AXDR_ERROR && errp->re_status == ARPC_SUCCESS) {
			errp->re_status = ARPC_CANTDECODERES;
		}
		if (errp->re_status != ARPC_SUCCESS && cco->cco_resp && 
		    (cco->cco_flags & CCO_FLG_RESULT_ALLOCED) != 0) {
			/* free up args if we have them on error (prevents
			 * some leak cases)..
			 */
			axdr_free(cco->cco_xres, cco->cco_resp);
			free(cco->cco_resp);
			cco->cco_resp = NULL;
			cco->cco_flags &= ~CCO_FLG_RESULT_ALLOCED;
		}
		cco->cco_state = CCO_STATE_DONE;
		/* fallthrough */
	case CCO_STATE_DONE:
		if (ioep->iep_debug_file) {
			errp = &cco->cco_rpc_err;
			/* include body info in msg dump, if we have it */
			if (cco->cco_resp &&
			    errp->re_status == ARPC_SUCCESS) {
				msg->arm_reply.arp_acpt.aar_results.where = 
					cco->cco_resp;
				msg->arm_reply.arp_acpt.aar_results.proc = 
					cco->cco_xres;
			}

			ar_log_msg(ioep, msg, "got reply:");

			/* clear pointers to body, since the storage is 
			 * managed seperately.
			 */
			msg->arm_reply.arp_acpt.aar_results.where = NULL;
			msg->arm_reply.arp_acpt.aar_results.proc = NULL;
		}
		
		ioep->iep_clnt_reply = NULL;
		*ccop = cco;
		break;
	default:
		ar_ioep_fatal_error(ioep);
		return AXDR_ERROR;
	}

	return rval;
}


ar_clnt_call_obj_t
ar_clnt_new_rx_msg(ar_ioep_t ioep)
{
	ar_clnt_call_obj_t cco;

	cco = ioep->iep_clnt_reply;
	ioep->iep_clnt_reply = NULL;
	return cco;
}

struct async_state_s {
	ar_client_t 	*rh;
	bool_t		done;
	arpc_err_t 	result;
};
	

static void
sync_callback(ar_clnt_call_obj_t cco, void *arg, const arpc_err_t *stat,
	      void *result)
{
	struct async_state_s *state;

	state = (struct async_state_s *)arg;

	state->done = TRUE;
	state->result = *stat;
}


ar_stat_t
ar_clnt_call(ar_client_t *rh, arpcproc_t proc, axdrproc_t xargs,
	     void *argsp, axdrproc_t xres, void *resp, int resplen,
	     struct timespec *tsp, arpc_err_t *errp)
{
	struct async_state_s state;
	ar_ioctx_t ioctx;
	bool_t freectx;
	struct timespec ts;
	ar_clnt_call_obj_t cco;
	int err;

	memset(&state, 0, sizeof(state));
	state.done = FALSE;
	state.result.re_status = ARPC_SUCCESS;
	state.rh = rh;
	freectx = FALSE;

	/* add some sanity since allocation in xdr is based on 
	 * null checks.
	 */
	if (resplen > 0) {
		memset(resp, 0, resplen);
	}

	ioctx = rh->cl_ioctx;
	if (!ioctx) {
		err = ar_ioctx_create(&ioctx);
		if (err != 0) {
			state.result.re_status = ARPC_SYSTEMERROR;
			state.result.re_errno = err;
			goto error;
		}
		freectx = TRUE;
		rh->cl_ioctx = ioctx;
	}

	if (tsp) {
		ts = *tsp;
	} else {
		ts = rh->cl_defwait;
	}

	err = (*rh->cl_ops->cl_call)(rh, proc, xargs, argsp, TRUE, 
				     xres, resp, resplen, sync_callback,
				     &state, &ts, &cco);
	if (err != 0) {
		state.result.re_status = ARPC_SYSTEMERROR;
		state.result.re_errno = err;
		goto error;
	}

	while (!state.done) {
		err = ar_ioctx_loop(ioctx);
		if (err != 0) {
			if (err == EINTR) {
				continue;
			}

			(*rh->cl_ops->cl_cancel)(rh, cco); 
			state.result.re_status = ARPC_SYSTEMERROR;
			state.result.re_errno = err;
			goto error;
		}
	}

 error:
	if (freectx) {
		rh->cl_ioctx = NULL;
		ar_ioctx_destroy(ioctx);
	}

	/* more sanity, free up any partial data */
	if (state.result.re_status != ARPC_SUCCESS && resplen > 0) {
		axdr_free(xres, resp);
	
		/* zero buffer again */
		memset(resp, 0, resplen);
	}
	
	if (errp) {
		*errp = state.result;
	}
	return state.result.re_status;
}

int
ar_clnt_cco_init(ar_clnt_call_obj_t cco, ar_client_t *cl, ar_auth_t *auth, 
		 struct ar_xid_state_s *xids, arpcproc_t proc, 
		 axdrproc_t xargs, void *argsp, bool_t inplace, 
		 axdrproc_t xres, void *resp, int ressize, 
		 ar_clnt_async_cb_t cb, void *cb_arg, struct timespec *tout)
{
	axdr_state_t	xdr;
	axdr_ret_t	ret;
	char		*buf;
	int		size;

	if (!cco || !cl || !auth || !xids || !xargs || !cb) {
		return EINVAL;
	}

	memset(cco, 0, sizeof(*cco));

	cco->cco_client = cl;
	cco->cco_state = CCO_STATE_PENDING;
	cco->cco_xid = ar_xid_get(xids);
	if (tout && ar_time_not_ok(tout) == FALSE) {
		cco->cco_timeout = *tout;
	} else {
		/* default timeout */
		cco->cco_timeout.tv_sec = CG_DEF_RPC_TIMEOUT_SECS;
		cco->cco_timeout.tv_nsec = CG_DEF_RPC_TIMEOUT_NSECS;
	}

	ar_gettime(&cco->cco_start);

	cco->cco_rpc_err.re_status = ARPC_SUCCESS;
	cco->cco_xres = xres;
	cco->cco_refcnt = 1;	/* 1 ref for the user */
	cco->cco_call.arm_xid = cco->cco_xid;
	cco->cco_call.arm_direction = AR_CALL;
	cco->cco_call.arm_call.acb_rpcvers = 2;
	cco->cco_call.arm_call.acb_prog = cl->cl_prog;
	cco->cco_call.arm_call.acb_vers = cl->cl_ver;
	cco->cco_call.arm_call.acb_proc = proc;
	cco->cco_call.arm_call.acb_body_where = argsp;
	cco->cco_call.arm_call.acb_body_proc = xargs;

	if (!AR_AUTH_MARSHALL_MSG(auth, &cco->cco_call)) {
		return EPERM;
	}

	if (resp) {
		cco->cco_resp = resp;
		cco->cco_ressize = -1;
		cco->cco_flags &= ~CCO_FLG_RESULT_ALLOCED;
	} else if (ressize >= 0) {
		cco->cco_resp = NULL;
		cco->cco_ressize = ressize;
	} else {
		AR_AUTH_CLEANUP_MSG(auth, &cco->cco_call);
		return EINVAL;
	}

	if (inplace) {
		cco->cco_rtype = CLNT_ARGS_TYPE_XDR;
		cco->cco_args.cco_xdr.obj = &cco->cco_call;
		cco->cco_args.cco_xdr.xdrp = (axdrproc_t)axdr_msg;
	} else {
		size = axdr_sizeof((axdrproc_t)axdr_msg, &cco->cco_call);
		buf = malloc(size);
		if (!buf) {
			AR_AUTH_CLEANUP_MSG(auth, &cco->cco_call);
			free(cco);
			return ENOMEM;
		}
		memset(buf, 0, size);
		axdrmem_create(&xdr, buf, size, AXDR_ENCODE);

		ret = axdr_msg(&xdr, &cco->cco_call);
		axdr_destroy(&xdr);
		if (ret != AXDR_DONE) {
			AR_AUTH_CLEANUP_MSG(auth, &cco->cco_call);
			free(buf);
			return EINVAL;
		}

		cco->cco_rtype = CLNT_ARGS_TYPE_BUF;
		cco->cco_args.cco_buffer.buf = buf;
		cco->cco_args.cco_buffer.len = size;
	}

	if (cl->cl_ioep) {
		ar_log_msg(cl->cl_ioep, &cco->cco_call, "sending call:");
	}

	cco->cco_cb = cb;
	cco->cco_cb_arg = cb_arg;

	return 0;
}

void
ar_clnt_cco_cleanup(ar_auth_t *auth, ar_clnt_call_obj_t cco)
{
	if (auth) {
		AR_AUTH_CLEANUP_MSG(auth, &cco->cco_call);
	}

	/* NOTE: if the user provides their own result buffer, it is
	 * there responsibility to clean up the result on error.
	 * (the sync clnt_call wrapper does this for users.)
	 * When we allocate the memory, we clean up. (async call path)
	 */
	if (cco->cco_resp && 
	    (cco->cco_flags & CCO_FLG_RESULT_ALLOCED) != 0) {
		axdr_free(cco->cco_xres, cco->cco_resp);
		if (cco->cco_ressize > 0) {
			memset(cco->cco_resp, 0, cco->cco_ressize);
		}
		free(cco->cco_resp);
		cco->cco_resp = NULL;
	}

	if (cco->cco_rtype == CLNT_ARGS_TYPE_BUF) {
		if (cco->cco_args.cco_buffer.buf != NULL) {
			free(cco->cco_args.cco_buffer.buf);
		}
		cco->cco_args.cco_buffer.buf = NULL;
		cco->cco_args.cco_buffer.len = 0;
	}
}

int
ar_clnt_cco_reauth(ar_auth_t *auth, ar_clnt_call_obj_t cco)
{
	axdr_state_t		xdrs;
	axdr_ret_t	rval;
	uint32_t	credlen;
	uint32_t	verflen;
	int		off;
	char		*nbuf;
	char		*obuf;
	int		len;
	int		len1;
	int		len2;

	if (!cco || !auth) {
		return EINVAL;
	}

	AR_AUTH_CLEANUP_MSG(auth, &cco->cco_call);
	
	if (!AR_AUTH_MARSHALL_MSG(auth, &cco->cco_call)) {
		return EPERM;
	}

	switch (cco->cco_rtype) {
	case CLNT_ARGS_TYPE_XDR:
		/* we'll pick up new auth automatically */
		return 0;
	case CLNT_ARGS_TYPE_BUF:
		/* 5 longs before the cred and verf */
		/* each opaque auth is enum followed by opaque */
		obuf = cco->cco_args.cco_buffer.buf;
		off = 4*5;
		/* skip the cred auth type enum to get opaque byte length */
		off += 4;
		credlen = *((uint32_t *)&obuf[off]);
		credlen = ntohl(credlen);
		credlen = (credlen + 3) & ~3;
		/* skip opaque len and data */
		off += 4 + credlen;
		/* skip the verf auth tyep enum */
		off += 4;
		verflen = *((uint32_t *)&obuf[off]);
		verflen = ntohl(verflen);
		verflen = (verflen + 3) & ~3;
		/* skip opaque len and data */
		off += 4 + verflen;
		len1 = off;

		/* make sure we don't have a body handler */
		cco->cco_call.arm_call.acb_body_where = NULL;
		cco->cco_call.arm_call.acb_body_proc = NULL;
		
		len2 = axdr_sizeof((axdrproc_t)axdr_msg, &cco->cco_call);
		len = len2 + cco->cco_args.cco_buffer.len - len1;
		if (len1 != len2) {
			nbuf = malloc(len);
			if (!nbuf) {
				return ENOMEM;
			}
		} else {
			nbuf = obuf;
		}
		axdrmem_create(&xdrs, nbuf, len2, AXDR_ENCODE);
		rval = axdr_msg(&xdrs, &cco->cco_call);
		axdr_destroy(&xdrs);
		if (rval != AXDR_DONE) {
			if (nbuf != obuf) {
				free(nbuf);
			}
			return EPARSE;
		}

		if (nbuf != obuf) {
			memcpy(&nbuf[len2], &obuf[len1], len - len2);
			free(obuf);
		}
		cco->cco_args.cco_buffer.buf = nbuf;
		cco->cco_args.cco_buffer.len = len;
		return 0;
	default:
		return EINVAL;
	}
}

int 
ar_clnt_call_async_copy(ar_client_t *cl, arpcproc_t num, 
		     axdrproc_t argsx, void *argsp,
		     axdrproc_t retx, int retlen, ar_clnt_async_cb_t cb, 
		     void *cb_arg, struct timespec *tout,
		     ar_clnt_call_obj_t *ccop)
{
	if (!cl || !cl->cl_ops || !cl->cl_ops->cl_call) {
		return ENXIO;
	}

	return (*cl->cl_ops->cl_call)(cl, num, argsx, argsp, FALSE, retx, NULL,
				      retlen, cb, cb_arg, tout, ccop);
}

int
ar_clnt_call_async_inplace(ar_client_t *cl, arpcproc_t num, axdrproc_t argsx, 
			void *argsp, axdrproc_t retx, int retlen, 
			ar_clnt_async_cb_t cb, void *cb_arg,
			struct timespec *tout, ar_clnt_call_obj_t *ccop)
{
	if (!cl || !cl->cl_ops || !cl->cl_ops->cl_call) {
		return ENXIO;
	}

	return (*cl->cl_ops->cl_call)(cl, num, argsx, argsp, TRUE, retx, NULL,
				      retlen, cb, cb_arg, tout, ccop);
}

int
ar_clnt_call_geterr(ar_clnt_call_obj_t cco, arpc_err_t *errp)
{
	if (!cco || !errp) {
		return EINVAL;
	}

	if (cco->cco_state != CCO_STATE_DONE &&
	    cco->cco_state != CCO_STATE_DEAD) {
		return EBUSY;
	}

	*errp = cco->cco_rpc_err;
	return 0;
}

void
ar_clnt_call_cancel(ar_clnt_call_obj_t handle)
{
	ar_client_t *cl;
	struct clnt_ops *ops;

	if (!handle) {
		return;
	}

	cl = handle->cco_client;
	assert(cl != NULL);
	ops = cl->cl_ops;
	assert(ops != NULL);

	(*ops->cl_cancel)(cl, handle);
}


void
ar_clnt_destroy(ar_client_t *cl)
{
	if (!cl || !cl->cl_ops || !cl->cl_ops->cl_destroy) {
		return;
	}

	RPCTRACE(cl->cl_ioctx, 2, "ar_clnt_destroy(): cl %p\n", cl);
	(*cl->cl_ops->cl_destroy)(cl);
}

int
ar_clnt_attr_init(ar_clnt_attr_t *attr)
{
	if (!attr) {
		return EINVAL;
	}
	memset(attr, 0, sizeof(*attr));

	attr->ca_minver = 0;
	attr->ca_maxver = 0;	/* do we want -1 here? */
	attr->ca_create_tmout.tv_sec = CG_DEF_CONN_TIMEOUT_SECS;
	attr->ca_create_tmout.tv_nsec = CG_DEF_CONN_TIMEOUT_NSECS;

	return 0;
}

int
ar_clnt_attr_set_pkcs12(ar_clnt_attr_t *attr, const char *passwd, 
			uint8_t *pkcs12, uint32_t len)
{
	if (!attr) {
		return EINVAL;
	}
	if ((len > 0 && !pkcs12) ||
	    (len == 0 && pkcs12 != NULL)) {
		return EFAULT;
	}

	attr->ca_pkcs12_passwd = passwd;
	attr->ca_pkcs12 = pkcs12;
	attr->ca_pkcs12_len = len;

	return 0;
}


int
ar_clnt_attr_set_tls(ar_clnt_attr_t *attr, void *arg, 
		     ar_tls_setup_cb_t setup, ar_tls_verify_cb_t verify,
		     ar_tls_info_cb_t info)
{
	if (!attr) {
		return EINVAL;
	}
	attr->ca_tls_arg = arg;
	attr->ca_tls_setup_cb = setup;
	attr->ca_tls_verify_cb = verify;
	attr->ca_tls_info_cb = info;

	return 0;
}


int
ar_clnt_attr_set_recvsize(ar_clnt_attr_t *attr, int recvsize)
{
	if (!attr) {
		return EINVAL;
	}
	attr->ca_recvsz = recvsize;
	return 0;
}

int
ar_clnt_attr_set_sendsize(ar_clnt_attr_t *attr, int sendsize)
{
	if (!attr) {
		return EINVAL;
	}
	attr->ca_sendsz = sendsize;
	return 0;
}

int
ar_clnt_attr_set_minver(ar_clnt_attr_t *attr, arpcvers_t vers)
{
	if (!attr) {
		return EINVAL;
	}
	attr->ca_minver = vers;
	return 0;
}

int
ar_clnt_attr_set_maxver(ar_clnt_attr_t *attr, arpcvers_t vers)
{
	if (!attr) {
		return EINVAL;
	}
	attr->ca_maxver = vers;
	return 0;
}

int
ar_clnt_attr_set_create_timeout(ar_clnt_attr_t *attr, 
				const struct timespec *tout)
{
	if (!attr) {
		return EINVAL;
	}

	if (tout) {
		attr->ca_create_tmout = *tout;
	} else {
		attr->ca_create_tmout.tv_sec = CG_DEF_CONN_TIMEOUT_SECS;
		attr->ca_create_tmout.tv_nsec = CG_DEF_CONN_TIMEOUT_NSECS;
	}

	return 0;
}

int
ar_clnt_attr_set_svc(ar_clnt_attr_t *attr, bool_t allow_svc, void *svc_user)
{
	if (!attr) {
		return EINVAL;
	}

	if (allow_svc) {
		attr->ca_flags |= CA_FLG_ALLOW_SVC;
	} else {
		attr->ca_flags &= ~CA_FLG_ALLOW_SVC;
	}
	attr->ca_svc_user = svc_user;

	return 0;
}


int
ar_clnt_attr_set_required(ar_clnt_attr_t *attr, bool_t required)
{
	if (!attr) {
		return EINVAL;
	}

	if (required) {
		attr->ca_flags |= CA_FLG_REQUIRED;
	} else {
		attr->ca_flags &= ~CA_FLG_REQUIRED;
	}

	return 0;
}

int
ar_clnt_attr_set_conncb(ar_clnt_attr_t *attr, ar_conn_cb_t cb, void *cb_arg)
{
	if (!attr || !cb) {
		return EINVAL;
	}

	attr->ca_conn_cb = cb;
	attr->ca_conn_arg = cb_arg;
	return 0;
}

int
ar_clnt_attr_set_disconcb(ar_clnt_attr_t *attr, 
			  ar_discon_cb_t cb, void *cb_arg)
{
	if (!attr || !cb) {
		return EINVAL;
	}

	attr->ca_discon_cb = cb;
	attr->ca_discon_arg = cb_arg;
	return 0;
}

int
ar_clnt_attr_set_debug(ar_clnt_attr_t *attr, FILE *fp, const char *prefix)
{
	if (!attr) {
		return EINVAL;
	}

	attr->ca_debug_file = fp;
	attr->ca_debug_prefix = prefix;
	return 0;
}


int
ar_clnt_attr_destroy(ar_clnt_attr_t *attr)
{
	if (!attr) {
		return EINVAL;
	}
	return 0;
}

bool_t
ar_clnt_control_default(ar_client_t *rh, u_int req, char *info)
{
	ar_ioep_t ioep;

	switch (req) {
	case AR_CLSET_DEBUG: {
		ar_clnt_debug_t *rcd;
		char *cp;

		rcd = (ar_clnt_debug_t *)info;
		if (!rcd) {
			return FALSE;
		}

		ioep = rh->cl_ioep;
		if (!ioep) {
			return FALSE;
		}

		if (rcd->prefix) {
			cp = strdup(rcd->prefix);
			if (!cp) {
				return FALSE;
			}
		} else {
			cp = NULL;
		}

		ioep->iep_debug_file = rcd->fout;
		if (ioep->iep_debug_prefix) {
			free(ioep->iep_debug_prefix);
		}
		ioep->iep_debug_prefix = cp;
		return TRUE;
	}
	default:
		/* let transport specific control handling it */
		break;
			
	}

	return FALSE;
}

bool_t
ar_clnt_control(ar_client_t *rh, u_int req, void *info)
{
	if (!rh) {
		return FALSE;
	}

	if (!rh->cl_ops || !rh->cl_ops->cl_control) {
		return FALSE;
	}

	return (*rh->cl_ops->cl_control)(rh, req, info);
}

const char *
ar_strstat(ar_stat_t stat)
{
	const char *ret;

	switch (stat) {
	case ARPC_SUCCESS:
		ret = "RPC: Success";
		break;
	case ARPC_CANTENCODEARGS:
		ret = "RPC: Can't encode arguments";
		break;
	case ARPC_CANTDECODERES:
		ret = "RPC: Can't decode result";
		break;
	case ARPC_CANTSEND:
		ret = "RPC: Unable to send";
		break;
	case ARPC_CANTRECV:
		ret = "RPC: Unable to receive";
		break;
	case ARPC_TIMEDOUT:
		ret = "RPC: Timed out";
		break;
	case ARPC_INTR:
		ret = "RPC: Operation interrupted";
		break;
	case ARPC_VERSMISMATCH:
		ret = "RPC: Incompatible versions of RPC";
		break;
	case ARPC_AUTHERROR:
		ret = "RPC: Authentication error";
		break;
	case ARPC_PROGUNAVAIL:
		ret = "RPC: Program is unavailable";
		break;
	case ARPC_PROGVERSMISMATCH:
		ret = "RPC: Program/version mismatch";
		break;
	case ARPC_PROCUNAVAIL:
		ret = "RPC: Procedure unavailable";
		break;
	case ARPC_CANTDECODEARGS:
		ret = "RPC: Server can't decode arguments";
		break;
	case ARPC_SYSTEMERROR:
		ret = "RPC: Remote system error";
		break;
	case ARPC_UNKNOWNHOST:
		ret = "RPC: Unknown host";
		break;
	case ARPC_UNKNOWNPROTO:
		ret = "RPC: Unknown protocol";
		break;
	case ARPC_UNKNOWNADDR:
		ret = "RPC: Unknown address";
		break;
	case ARPC_NOBROADCAST:
		ret = "RPC: Broadcast not supported";
		break;
	case ARPC_RPCBFAILURE:
		ret = "RPC: Bind lookup failed";
		break;
	case ARPC_PROGNOTREGISTERED:
		ret = "RPC: Program not registered";
		break;
	case ARPC_N2AXLATEFAILURE:
		ret = "RPC: Name to address translation failed";
		break;
	case ARPC_TLIERROR:
		ret = "RPC: Transport layer failure";
		break;
	case ARPC_FAILED:
		ret = "RPC: Failed (unspecified error)";
		break;
	case ARPC_INPROGRESS:
		ret = "RPC: Operation in progress";
		break;
	case ARPC_CANTCONNECT:
		ret = "RPC: Connection failed";
		break;
	case ARPC_XPRTFAILED:
		ret = "RPC: Create server link failed";
		break;
	case ARPC_CANTCREATESTREAM:
		ret = "RPC: Stream create failed";
		break;
	case ARPC_ERRNO:
		ret = "RPC: Local system error";
		break;
	default:
		ret = "<UNKNOWN>";
		break;
	}

	return ret;
}

const char *
ar_strauthstat(ar_auth_stat_t stat)
{
	const char *ret;

	switch (stat) {
	case AR_AUTH_OK:
		ret = "AUTH: Ok";
		break;
	case AR_AUTH_BADCRED:
		ret = "AUTH: Invalid client credential";
		break;
	case AR_AUTH_REJECTEDCRED:
		ret = "AUTH: Server rejected credential";
		break;
	case AR_AUTH_BADVERF:
		ret = "AUTH: Invalid client verifier";
		break;
	case AR_AUTH_REJECTEDVERF:
		ret = "AUTH: Server rejected verifier";
		break;
	case AR_AUTH_TOOWEAK:
		ret = "AUTH: Client credential too weak";
		break;
	case AR_AUTH_INVALIDRESP:
		ret = "AUTH: Invalid server verifier";
		break;
	case AR_AUTH_FAILED:
		ret = "AUTH: Failed (unspecified error)";
		break;
	case AR_AUTH_KERB_GENERIC :
		ret = "AUTH: Kerberos generic error";
		break;
	case AR_AUTH_TIMEEXPIRE :
		ret = "AUTH: Credential lifetime expired";
		break;
	case AR_AUTH_TKT_FILE :
		ret = "AUTH: Error with ticket file";
		break;
	case AR_AUTH_DECODE :
		ret = "AUTH: Decode authenticator failed";
		break;
	case AR_AUTH_NET_ADDR :
		ret = "AUTH: Wrong network address in ticket";
		break;
	default:
		ret = "<UNKNOWN>";
		break;
	}
	return ret;
}

static void
ar_astrerror_helper(const arpc_err_t *errp, size_t *lenp, char *buf)
{
	const char *base;
	const char *extra;
	char tbuf[32];
	size_t inlen;
	size_t len;
	size_t off;

	inlen = *lenp;
	off = 0;
	base = ar_strstat(errp->re_status);
	if (buf) {
		snprintf(&buf[off], inlen - off, "%s", base);
	}
	len = strlen(base);
	off += len;

	switch (errp->re_status) {
	case ARPC_AUTHERROR:
		extra = ar_strauthstat(errp->re_why);
		break;
	case ARPC_VERSMISMATCH:
	case ARPC_PROGVERSMISMATCH:
		snprintf(tbuf, sizeof(tbuf), "Valid range: %u-%u", 
			 errp->re_vers.low, errp->re_vers.high);
		extra = tbuf;
		break;
	case ARPC_FAILED:
		snprintf(tbuf, sizeof(tbuf), "Error codes: %d, %d", 
			 errp->re_lb.s1, errp->re_lb.s2);
		extra = tbuf;
		break;
	case ARPC_ERRNO:
		extra = strerror(errp->re_errno);
		break;
	default:
		extra = NULL;
		break;
	}

	if (extra) {
		len = 2 + strlen(extra);
		if (buf) {
			snprintf(&buf[off], inlen - off, ": %s", extra);
		}
		off += len;
	}

	/* add 1 for null */
	off++;

	*lenp = off;
}


char *
ar_astrerror(const arpc_err_t *errp)
{
	size_t len;
	size_t off;
	char *ret;

	len = 0;
	ar_astrerror_helper(errp, &len, NULL);
	ret = malloc(len + 1);
	if (!ret) {
		return NULL;
	}
	off = len;
	ar_astrerror_helper(errp, &off, ret);
	if (off != len) {
		/* something went horribly wrong.. */
		free(ret);
		ret = NULL;
	}
	return ret;
}
	
void
ar_strerror(const arpc_err_t *errp, char *buf, size_t len)
{
	char *cp;

	if (!errp || !buf) {
		return;
	}

	cp = ar_astrerror(errp);
	if (cp) {
		snprintf(buf, len, "%s", cp);
		free(cp);
	} else {
		snprintf(buf, len, "error %d", errp->re_status);
	}
}

char *
ar_astrcreateerror(const arpc_createerr_t *errp)
{
	const char *cp;
	char *base;
	char *ret;
	int len;

	base = ar_astrerror(&errp->cf_error);
	/* generally, this is the same as an arpc_err_t... */
	if (errp->cf_stat != ARPC_RPCBFAILURE || 
	    errp->cf_error.re_status == ARPC_RPCBFAILURE) {
		return base;
	}
	
	cp = ar_strstat(ARPC_RPCBFAILURE);
	len = strlen(cp) + 2 + strlen(base) + 1;
	ret = malloc(len);
	if (!len) {
		free(base);
		return NULL;
	}
	snprintf(ret, len, "%s: %s", cp, base);
	free(base);
	base = NULL;

	return ret;
}

void
ar_strcreateerror(const arpc_createerr_t *errp, char *buf, size_t len)
{
	char *cp;

	if (!errp || !buf) {
		return;
	}

	cp = ar_astrcreateerror(errp);
	if (cp) {
		snprintf(buf, len, "%s", cp);
		free(cp);
	} else {
		snprintf(buf, len, "error %d", errp->cf_stat);
	}
}
