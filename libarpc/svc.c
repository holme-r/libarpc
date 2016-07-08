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
 * svc.c, Server-side remote procedure call interface.
 *
 * There are two sets of procedures here.  The xprt routines are
 * for handling transport handles.  The svc routines handle the
 * list of service routines.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#include "compat.h"

#include <sys/types.h>
#include <sys/poll.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <libarpc/arpc.h>
#include "rpc_com.h"

#define	RQCRED_SIZE	400		/* this size is excessive */

#define SVC_VERSQUIET 0x0001		/* keep quiet about vers mismatch */
#define version_keepquiet(xp) ((u_long)(xp)->xp_p3 & SVC_VERSQUIET)

#define max(a, b) (a > b ? a : b)

static void iep_noprog(ar_ioep_t ioep, uint32_t xid);
static int svc_sendreply(ar_svc_xprt_t *xprt, uint32_t xid, 
    axdrproc_t xdr_results, void *xdr_location);
static void ar_svcerr_noproc(ar_svc_xprt_t *xprt, uint32_t xid);
static void ar_svcerr_decode(ar_svc_xprt_t *xprt, u_int32_t xid, 
    ar_svc_call_obj_t sco);
static void ar_svcerr_auth(ar_svc_xprt_t *xprt, uint32_t xid, 
    ar_auth_stat_t why);
static void ar_svcerr_weakauth(ar_svc_xprt_t *xprt, uint32_t xid);
static void ar_svcerr_noprog(ar_svc_xprt_t *xprt, uint32_t xid);
static void ar_svcerr_progvers(ar_svc_xprt_t *xprt, uint32_t xid, 
    arpcvers_t low_vers, arpcvers_t high_vers);


static void svc_setup_err_reply(arpc_msg_t *rply, uint32_t xid, 
				const ar_opaque_auth_t *verf, 
				const arpc_err_t *errp)
{
	ar_accept_stat_t	astat;

	rply->arm_direction = AR_REPLY;
	rply->arm_xid = xid;
	rply->arm_reply.arp_stat = AR_MSG_ACCEPTED; 
	rply->arm_acpted_rply.aar_verf = *verf;

	astat = AR_SUCCESS;

	switch (errp->re_status) {
	case ARPC_CANTDECODEARGS:
		astat = AR_GARBAGE_ARGS;
		break;
	case ARPC_PROCUNAVAIL:
		astat = AR_PROC_UNAVAIL;
		break;
	case ARPC_PROGVERSMISMATCH:
		astat = AR_PROG_MISMATCH;
		rply->arm_acpted_rply.aar_vers.low = 
			(u_int32_t)errp->re_vers.low;
		rply->arm_acpted_rply.aar_vers.high = 
			(u_int32_t)errp->re_vers.high;
		break;
	case ARPC_AUTHERROR:
		rply->arm_reply.arp_stat = AR_MSG_DENIED;
		rply->arm_rjcted_rply.arj_stat = AR_AUTH_ERROR;
		rply->arm_rjcted_rply.arj_why = errp->re_why;
		break;
	case ARPC_PROGUNAVAIL:
		astat = AR_PROG_UNAVAIL;
		break;
	case ARPC_SYSTEMERROR:
	default:
		astat = AR_SYSTEM_ERR;
	}
	if (astat != AR_SUCCESS) {
		rply->arm_acpted_rply.aar_stat = astat;
	}
}



axdr_ret_t
ar_svc_handle_call(axdr_state_t *xdrs, ar_ioep_t ioep, arpc_msg_t *msg, 
		   ar_svc_call_obj_t *scop)
{
	arpc_msg_t		*rply;
	ar_auth_stat_t		why;
	ar_svc_req_t		r;
	ar_ioctx_t		ioctx;
	ar_svc_call_obj_t	sco;
	ar_svc_call_obj_t       sco_async;
	svc_callout_t		*cout;
	arpcvers_t		low_vers;
	arpcvers_t		high_vers;
	ar_svc_handler_fn_t	callback;
	const struct xp_ops	*xops;
	ar_svc_xprt_t			*xp;
	axdr_ret_t		rval;
	bool_t			prog_found;
	int			result;
	axdrproc_t		argsxdr;
	int			argslen;
	axdrproc_t		resultxdr;
	int			resultlen;
	int			err;

	if (!xdrs || !ioep || !msg || !scop) {
		return AXDR_ERROR;
	}

	*scop = NULL;

	sco = ioep->iep_svc_call;
	ioctx = ioep->iep_ioctx;
	if (!ioctx) {
		return AXDR_ERROR;
	}

	if ((ioep->iep_flags & IEP_FLG_ALLOW_SVC) == 0) {
		/* no serving allowed. Error out */
		iep_noprog(ioep, msg->arm_xid);
		return AXDR_DONE;
	}

	/* Skip msg if xid matches an async one */
	TAILQ_FOREACH(sco_async, &ioep->iep_svc_async_calls,
		      sco_listent) {
		if (sco_async->sco_req.rq_xid == msg->arm_xid) {
			ar_log_msg(ioep, msg, "filtering dup call (async):");
			return AXDR_DONE;
		}
	}

	if (!sco) {
		/* have call object.  We have to look it up and 
		 * process it */
		xp = ioep->iep_svc_ctx;
		if (!xp) {
			iep_noprog(ioep, msg->arm_xid);
			/* no server side registered.  Ignore calls. */
			return AXDR_DONE;
		}
		r.rq_xprt = xp;
		r.rq_xid = msg->arm_xid;
		r.rq_prog = msg->arm_call.acb_prog;
		r.rq_vers = msg->arm_call.acb_vers;
		r.rq_proc = msg->arm_call.acb_proc;
		r.rq_cred = msg->arm_call.acb_cred;
		r.rq_err.re_status = ARPC_SUCCESS;

		why = ar_svc_authenticate(&r, msg);
		if (why != AR_AUTH_OK) {
			ar_svcerr_auth(xp, r.rq_xid, why);
			return AXDR_DONE;
		}

		/* now find the correct service */
		low_vers = (arpcvers_t) -1L;
		high_vers = (arpcvers_t) 0L;
		prog_found = FALSE;
		TAILQ_FOREACH(cout, &ioctx->icx_svc_list, sc_listent) {
			if (cout->sc_prog == r.rq_prog && 
			    cout->sc_vers == r.rq_vers) {
				break;
			}
			if (cout->sc_prog == r.rq_prog) {
				prog_found = TRUE;
				if (cout->sc_vers < low_vers) {
					low_vers = cout->sc_vers;
				}
				if (cout->sc_vers > high_vers) {
					high_vers = cout->sc_vers;
				}
			}
		}

		if (!cout) {
			/*
			 * if we got here, the program or version
			 * is not served ...
			 */
			if (prog_found) {
				ar_svcerr_progvers(xp, r.rq_xid, 
						low_vers, high_vers);
			} else {
				ar_svcerr_noprog(xp, r.rq_xid);
			}
			return AXDR_DONE;
		}

		if (!cout->sc_lookup) {
			ar_svcerr_noproc(xp, r.rq_xid);
			return AXDR_DONE;
		}

		(*cout->sc_lookup)(r.rq_proc, &callback, &argsxdr, &resultxdr, 
				   &argslen, &resultlen);
		if (!callback) {
			if (r.rq_proc == AR_NULLPROC) {
				svc_sendreply(xp, r.rq_xid, 
					      (axdrproc_t)axdr_void,
					      (char *)NULL);
			} else {
				ar_svcerr_noproc(xp, r.rq_xid);
			}
			return AXDR_DONE;
		}

		xops = xp->xp_ops;

		err = (*xops->xp_sco_alloc)(xp, &sco);
		if (err != 0) {
			ar_svcerr_systemerr(xp, r.rq_xid, NULL);
			return AXDR_DONE;
		}

		sco->sco_args = malloc(argslen);
		if (!sco->sco_args) {
			(*xops->xp_sco_destroy)(xp, sco);
			ar_svcerr_systemerr(xp, r.rq_xid, NULL);
			return AXDR_DONE;
		}
		sco->sco_result = malloc(resultlen);
		if (!sco->sco_result) {
			free(sco->sco_args);
			(*xops->xp_sco_destroy)(xp, sco);
			ar_svcerr_systemerr(xp, r.rq_xid, NULL);
			return AXDR_DONE;
		}
		memset(sco->sco_args, 0, argslen);
		memset(sco->sco_result, 0, resultlen);

		sco->sco_xp = xp;
		sco->sco_state = SCO_STATE_GET_ARGS;
		sco->sco_req = r;
		sco->sco_callback = callback;
		sco->sco_argsxdr = argsxdr;
		sco->sco_argslen = argslen;
		sco->sco_resultxdr = resultxdr;
		sco->sco_resultlen = resultlen;
		sco->sco_err.re_status = ARPC_SUCCESS;

		/* Release user refernce.  That only exists async responses 
		 * owned outside the library.
		 */
		assert((sco->sco_flags & SCO_FLG_USRREF_DEC) == 0);
		sco->sco_flags |= SCO_FLG_USRREF_DEC;
		sco->sco_refcnt--;

		ioep->iep_svc_call = sco;
	}

	xp = sco->sco_xp;
	xops = xp->xp_ops;

	switch (sco->sco_state) {
	case SCO_STATE_GET_ARGS:
		rval = (*sco->sco_argsxdr)(xdrs, sco->sco_args);
		if (rval != AXDR_DONE) {
			if (rval != AXDR_ERROR) {
				return rval;
			}
			if ((ioep->iep_flags & IEP_FLG_DESTROY) == 0) {
				/*
				 * not destroyed.  Try to let the other
				 * side know we had a decode error.
				 */
				ar_svcerr_decode(sco->sco_xp, 
						 sco->sco_req.rq_xid, sco);
			}

			(*xops->xp_sco_destroy)(xp, sco);

			return AXDR_ERROR;
		}

		sco->sco_state = SCO_STATE_CALL;
		/* fall through */
	case SCO_STATE_CALL:
		assert((sco->sco_flags & SCO_FLG_USRREF_DEC) != 0);

		/* if debugging is enabled, dump the request */
		if (ioep->iep_debug_file) {

			/* include body info in msg dump */
			msg->arm_call.acb_body_where = sco->sco_args;
			msg->arm_call.acb_body_proc = sco->sco_argsxdr;

			ar_log_msg(ioep, msg, "got call:");

			/* clear pointers to body, since the storage is 
			 * managed seperately.
			 */
			msg->arm_call.acb_body_where = NULL;
			msg->arm_call.acb_body_proc = NULL;
		}

		assert((sco->sco_flags & SCO_FLG_USRREF_DEC) != 0);

		/* give usrref back for the callback */
		sco->sco_flags &= ~SCO_FLG_USRREF_DEC;
		sco->sco_refcnt++;

		result = (*sco->sco_callback)(sco->sco_args, sco->sco_result, 
					      &sco->sco_req);
		if (result > 0) {
			/* SUCESS */
			if ((sco->sco_flags & SCO_FLG_ASYNC) != 0 &&
			    (sco->sco_flags & SCO_FLG_HNDLR_DONE) == 0) {
				/* 
				 * call handler result is deferred.
				 * We'll get notified when it's done.
				 * Everything is handled through the
				 * svc_call_obj at this point.
				 */
				ioep->iep_svc_call = NULL;
				sco->sco_state = SCO_STATE_ASYNC;
				TAILQ_INSERT_TAIL(&ioep->iep_svc_async_calls, 
						  sco, sco_listent);
				return AXDR_DONE;
			}
		} else if (sco->sco_req.rq_err.re_status == ARPC_SUCCESS) {
			/* Result not generated and no error flagged for
			 * reply, abort handling and don't respond 
			 */
			ioep->iep_svc_call = NULL;
			if ((sco->sco_flags & SCO_FLG_USRREF_DEC) == 0) {
				sco->sco_flags |= SCO_FLG_USRREF_DEC;
				sco->sco_refcnt--;
			}
			(*xops->xp_sco_destroy)(xp, sco);
			return AXDR_DONE;
		}


		/* call is done. */
		/* free up args */
		axdr_free(sco->sco_argsxdr, sco->sco_args);
		free(sco->sco_args);
		sco->sco_args = NULL;
		sco->sco_argsxdr = NULL;
		sco->sco_argslen = 0;

		/* release usr reference */
		if ((sco->sco_flags & SCO_FLG_USRREF_DEC) == 0) {
			sco->sco_flags |= SCO_FLG_USRREF_DEC;
			sco->sco_refcnt--;
		}
		
		/* Setup reply object */
		rply = &sco->sco_reply;
		memset(rply, 0, sizeof(*rply));

		if (result > 0) {
			/* success */
			rply->arm_direction = AR_REPLY;
			rply->arm_xid = sco->sco_req.rq_xid;
			rply->arm_reply.arp_stat = AR_MSG_ACCEPTED; 
			rply->arm_acpted_rply.aar_verf = ioep->iep_verf;
			rply->arm_acpted_rply.aar_stat = AR_SUCCESS;
			rply->arm_acpted_rply.aar_results.where = 
				sco->sco_result;
			rply->arm_acpted_rply.aar_results.proc = 
				sco->sco_resultxdr;
		} else {
			/* sending error, result not required */
			axdr_free(sco->sco_resultxdr, sco->sco_result);
			free(sco->sco_result);
			sco->sco_result = NULL;

			svc_setup_err_reply(rply, sco->sco_req.rq_xid,
					    &ioep->iep_verf, 
					    &sco->sco_req.rq_err);
		}

		ar_log_msg(ioep, rply, "sending reply:");

		*scop = sco;
		ioep->iep_svc_call = NULL;
		return AXDR_DONE;
	default:
		return AXDR_ERROR;
	}
}


ar_svc_call_obj_t
ar_svc_new_rx_msg(ar_ioep_t ioep)
{
	ar_svc_call_obj_t sco;
	
	sco = ioep->iep_svc_call;
	ioep->iep_svc_call = NULL;
	return sco;
}

int
ar_svc_reg(ar_svc_xprt_t *xprt, ar_svc_lookup_fn_t lookup, 
	      const arpcprog_t prog, const arpcvers_t ver)
{
	svc_callout_t *cout;
	ar_ioctx_t ctx;

	if (!xprt || !lookup) {
		return EINVAL;
	}

	ctx = xprt->xp_ioctx;

	TAILQ_FOREACH(cout, &ctx->icx_svc_list, sc_listent) {
		if (cout->sc_prog == prog && cout->sc_vers == ver) {
			if (cout->sc_lookup == lookup) {
				return 0;
			} else {
				return EBUSY;
			}
		}
	}

	cout = malloc(sizeof(*cout));
	if (!cout) {
		return ENOMEM;
	}
	memset(cout, 0, sizeof(*cout));

	cout->sc_prog = prog;
	cout->sc_vers = ver;
	cout->sc_lookup = lookup;
	
	TAILQ_INSERT_TAIL(&ctx->icx_svc_list, cout, sc_listent);
	return 0;
}

int
ar_svc_unreg(ar_svc_xprt_t *xprt, ar_svc_lookup_fn_t lookup, 
	     const arpcprog_t prog, const arpcvers_t ver)
{
	svc_callout_t *cout;
	svc_callout_t *cout_next;
	ar_ioctx_t ctx;
	int err;

	if (!xprt || !lookup) {
		return EINVAL;
	}

	ctx = xprt->xp_ioctx;

	err = ENOENT;
	for (cout = TAILQ_FIRST(&ctx->icx_svc_list); cout; cout = cout_next) {
		cout_next = TAILQ_NEXT(cout, sc_listent);
		if (cout->sc_prog != prog || cout->sc_vers != ver ||
		    cout->sc_lookup != lookup) {
			continue;
		}
		TAILQ_REMOVE(&ctx->icx_svc_list, cout, sc_listent);
		free(cout);
		err = EOK;
	}

	return err;
}


int
ar_svc_io_reg(ar_ioctx_t ctx, ar_svc_lookup_fn_t lookup,
    const arpcprog_t prog, const arpcvers_t ver)
{
        svc_callout_t *cout;

        if (!ctx || !lookup) {
                return EINVAL;
        }

        TAILQ_FOREACH(cout, &ctx->icx_svc_list, sc_listent) {
                if (cout->sc_prog == prog && cout->sc_vers == ver) {
			if (cout->sc_lookup == lookup) {
				return 0;
			} else {
				return EBUSY;
			}
                }
        }

        cout = malloc(sizeof(*cout));
        if (!cout) {
                return ENOMEM;
        }
        memset(cout, 0, sizeof(*cout));

        cout->sc_prog = prog;
        cout->sc_vers = ver;
        cout->sc_lookup = lookup;

        TAILQ_INSERT_TAIL(&ctx->icx_svc_list, cout, sc_listent);
        return 0;
}

int
ar_svc_io_unreg(ar_ioctx_t ctx, ar_svc_lookup_fn_t lookup,
    const arpcprog_t prog, const arpcvers_t ver)
{
        svc_callout_t *cout;
        svc_callout_t *cout_next;
        int err;

        if (!ctx || !lookup) {
                return EINVAL;
        }

        err = ENOENT;
        for (cout = TAILQ_FIRST(&ctx->icx_svc_list); cout; cout = cout_next) {
                cout_next = TAILQ_NEXT(cout, sc_listent);
                if (cout->sc_prog != prog || cout->sc_vers != ver ||
                    cout->sc_lookup != lookup) {
                        continue;
                }
                TAILQ_REMOVE(&ctx->icx_svc_list, cout, sc_listent);
                free(cout);
                err = EOK;
        }

        return err;
}

int
ar_svc_clnt_attach(ar_svc_xprt_t *xp, const arpcprog_t prog,
		   const arpcvers_t vers, ar_clnt_attr_t *attr, 
		   arpc_err_t *errp, ar_client_t **retp)
{
	ar_ioep_t	ioep;

	if (!xp || !retp) {
		return EINVAL;
	}

	ioep = xp->xp_ioep;
	if (!ioep || ((ioep->iep_flags & IEP_FLG_DESTROY) != 0)) {
		return EIO;
	}

	return (*ioep->iep_drv->epd_add_client)(ioep, prog, vers,
						attr, errp, retp);
}


void
ar_svc_sco_unlink(ar_svc_call_obj_t sco)
{
	ar_ioep_t ioep;
	ar_svc_xprt_t		*xp;

	if (!sco) {
		return;
	}

	if ((sco->sco_flags & SCO_FLG_UNLINKED) != 0) {
		/* already done */
		return;
	}

	xp = sco->sco_xp;
	assert(xp != NULL);
	ioep = xp->xp_ioep;

	switch (sco->sco_state) {
	case SCO_STATE_INIT:
	case SCO_STATE_DEAD:
		break;
	case SCO_STATE_GET_ARGS:
		assert(ioep != NULL);
		assert(ioep->iep_svc_call == sco);
		ioep->iep_svc_call = NULL;
		break;
	case SCO_STATE_CALL:
		assert(ioep != NULL);
		break;
	case SCO_STATE_ASYNC:
		assert(ioep != NULL);
		TAILQ_REMOVE(&ioep->iep_svc_async_calls, sco, sco_listent);
		break;
	case SCO_STATE_SEND_REPLY:
		assert(ioep != NULL);
		TAILQ_REMOVE(&ioep->iep_svc_replies, sco, sco_listent);
		break;
	case SCO_STATE_CACHED:
		assert(ioep != NULL);
		TAILQ_REMOVE(&ioep->iep_svc_cache, sco, sco_listent);
		break;
	default:
		assert(FALSE);
		break;
	}

	sco->sco_flags |= SCO_FLG_UNLINKED;
}


void
ar_svc_sco_cleanup(ar_svc_call_obj_t sco)
{
	ar_ioep_t	ioep;
	ar_svc_xprt_t		*xp;

	if (!sco) {
		return;
	}

	xp = sco->sco_xp;
	assert(xp != NULL);
	ioep = xp->xp_ioep;

	ar_svc_sco_unlink(sco);

	if (ioep) {
		assert(ioep->iep_svc_call != sco);
	}

	if (sco->sco_args) {
		if (sco->sco_argsxdr) {
			axdr_free(sco->sco_argsxdr, sco->sco_args);
		}
		free(sco->sco_args);
	}
	sco->sco_args = NULL;
	if (sco->sco_result) {
		if (sco->sco_resultxdr) {
			axdr_free(sco->sco_resultxdr, sco->sco_result);
		}
		free(sco->sco_result);
	}
	sco->sco_result = NULL;

	sco->sco_state = SCO_STATE_DEAD;
}

/* ******************* REPLY GENERATION ROUTINES  ************ */

/*
 * Send a reply to an rpc request
 */
static int
svc_sendreply(ar_svc_xprt_t *xprt, uint32_t xid, 
              axdrproc_t xdr_results, void *xdr_location)
{
	arpc_msg_t	rply;
	ar_ioep_t	ioep;
	
	assert(xprt != NULL);
	ioep = xprt->xp_ioep;
	if (!ioep) {
		return EINVAL;
	}
	memset(&rply, 0, sizeof(rply));

	rply.arm_direction = AR_REPLY;  
	rply.arm_reply.arp_stat = AR_MSG_ACCEPTED; 
	rply.arm_acpted_rply.aar_verf = ioep->iep_verf; 
	rply.arm_acpted_rply.aar_stat = AR_SUCCESS;
	rply.arm_acpted_rply.aar_results.where = xdr_location;
	rply.arm_acpted_rply.aar_results.proc = xdr_results;

	return (*ioep->iep_drv->epd_sendmsg)(ioep, &rply, NULL);
}

/*
 * No procedure error reply
 */
static void
ar_svcerr_noproc(ar_svc_xprt_t *xprt, uint32_t xid)
{
	arpc_msg_t	rply;
	ar_ioep_t	ioep;

	assert(xprt != NULL);

	ioep = xprt->xp_ioep;
	if (!ioep) {
		return;
	}
	memset(&rply, 0, sizeof(rply));

	rply.arm_xid = xid;
	rply.arm_direction = AR_REPLY;
	rply.arm_reply.arp_stat = AR_MSG_ACCEPTED;
	rply.arm_acpted_rply.aar_verf = ioep->iep_verf;
	rply.arm_acpted_rply.aar_stat = AR_PROC_UNAVAIL;

	(*ioep->iep_drv->epd_sendmsg)(ioep, &rply, NULL);
}

/*
 * Can't decode args error reply
 */
static void
ar_svcerr_decode(ar_svc_xprt_t *xprt, u_int32_t xid, ar_svc_call_obj_t sco)
{
	arpc_msg_t	rply; 
	ar_ioep_t	ioep;

	assert(xprt != NULL);

	ioep = xprt->xp_ioep;
	if (!ioep) {
		return;
	}
	memset(&rply, 0, sizeof(rply));

	rply.arm_xid = xid;
	rply.arm_direction = AR_REPLY; 
	rply.arm_reply.arp_stat = AR_MSG_ACCEPTED; 
	rply.arm_acpted_rply.aar_verf = ioep->iep_verf;
	rply.arm_acpted_rply.aar_stat = AR_GARBAGE_ARGS;

	(*ioep->iep_drv->epd_sendmsg)(ioep, &rply, sco);
}

/*
 * Some system error
 */
void
ar_svcerr_systemerr(ar_svc_xprt_t *xprt, uint32_t xid, ar_svc_call_obj_t sco)
	
{
	arpc_msg_t	rply; 
	ar_ioep_t	ioep;

	assert(xprt != NULL);

	ioep = xprt->xp_ioep;
	if (!ioep) {
		return;
	}
	memset(&rply, 0, sizeof(rply));

	rply.arm_direction = AR_REPLY; 
	rply.arm_reply.arp_stat = AR_MSG_ACCEPTED; 
	rply.arm_acpted_rply.aar_verf = ioep->iep_verf;
	rply.arm_acpted_rply.aar_stat = AR_SYSTEM_ERR;

	(*ioep->iep_drv->epd_sendmsg)(ioep, &rply, sco);
}

/*
 * Authentication error reply
 */
static void
ar_svcerr_auth(ar_svc_xprt_t *xprt, uint32_t xid, ar_auth_stat_t why)
{
	arpc_msg_t	rply;
	ar_ioep_t	ioep;

	assert(xprt != NULL);
	ioep = xprt->xp_ioep;
	assert(ioep != NULL);

	memset(&rply, 0, sizeof(rply));

	rply.arm_direction = AR_REPLY;
	rply.arm_xid = xid;
	rply.arm_reply.arp_stat = AR_MSG_DENIED;
	rply.arm_rjcted_rply.arj_stat = AR_AUTH_ERROR;
	rply.arm_rjcted_rply.arj_why = why;

	(*ioep->iep_drv->epd_sendmsg)(ioep, &rply, NULL);
}

/*
 * Auth too weak error reply
 */
static void
ar_svcerr_weakauth(ar_svc_xprt_t *xprt, uint32_t xid)
{
	assert(xprt != NULL);

	ar_svcerr_auth(xprt, xid, AR_AUTH_TOOWEAK);
}

static void
iep_noprog(ar_ioep_t ioep, uint32_t xid)
{
	arpc_msg_t	rply;

	assert(ioep != NULL);

	memset(&rply, 0, sizeof(rply));

	rply.arm_xid = xid;
	rply.arm_direction = AR_REPLY;   
	rply.arm_reply.arp_stat = AR_MSG_ACCEPTED;  
	rply.arm_acpted_rply.aar_verf = ioep->iep_verf;
	rply.arm_acpted_rply.aar_stat = AR_PROG_UNAVAIL;
	(*ioep->iep_drv->epd_sendmsg)(ioep, &rply, NULL);
}

/*
 * Program unavailable error reply
 */
static void 
ar_svcerr_noprog(ar_svc_xprt_t *xprt, uint32_t xid)
{
	ar_ioep_t	ioep;

	assert(xprt != NULL);
	ioep = xprt->xp_ioep;
	assert(ioep != NULL);

	iep_noprog(ioep, xid);
}

/*
 * Program version mismatch error reply
 */
static void 
ar_svcerr_progvers(ar_svc_xprt_t *xprt, uint32_t xid, arpcvers_t low_vers, 
		arpcvers_t high_vers)
{
	arpc_msg_t	rply;
	ar_ioep_t	ioep;

	assert(xprt != NULL);
	ioep = xprt->xp_ioep;
	assert(ioep != NULL);

	memset(&rply, 0, sizeof(rply));

	rply.arm_xid = xid;
	rply.arm_direction = AR_REPLY;
	rply.arm_reply.arp_stat = AR_MSG_ACCEPTED;
	rply.arm_acpted_rply.aar_verf = ioep->iep_verf;
	rply.arm_acpted_rply.aar_stat = AR_PROG_MISMATCH;
	rply.arm_acpted_rply.aar_vers.low = (u_int32_t)low_vers;
	rply.arm_acpted_rply.aar_vers.high = (u_int32_t)high_vers;

	(*ioep->iep_drv->epd_sendmsg)(ioep, &rply, NULL);
}

int
ar_svc_sco_init(ar_svc_call_obj_t sco, ar_svc_xprt_t *xp)
{

	if (!sco || !xp) {
		return EINVAL;
	}

	memset(sco, 0, sizeof(*sco));

	sco->sco_xp = xp;
	sco->sco_state = SCO_STATE_INIT;
	sco->sco_refcnt = 1;

	return 0;
}

int
ar_svc_attr_init(ar_svc_attr_t *attr)
{
	if (!attr) {
		return EINVAL;
	}

	memset(attr, 0, sizeof(*attr));

	attr->sa_sendsz = 0;
	attr->sa_recvsz = 0;
	attr->sa_dg_cache = FALSE;
	attr->sa_max_connections = 20;
	return 0;
}

int
ar_svc_attr_set_create_timeout(ar_svc_attr_t *attr,
			       const struct timespec *tout)
{
	if (!attr) {
		return EINVAL;
	}

	if (tout) {
		attr->sa_create_tmout = *tout;
	} else {
		tspecclear(&attr->sa_create_tmout);
	}

        return 0;
}

int
ar_svc_attr_set_pkcs12(ar_svc_attr_t *attr, const char *passwd,
		       uint8_t *pkcs12, uint32_t len)
{
	if (!attr) {
		return EINVAL;
	}
	if ((len > 0 && !pkcs12) ||
	    (len == 0 && pkcs12 != NULL)) {
		return EFAULT;
	}
	
	attr->sa_pkcs12_passwd = passwd;
	attr->sa_pkcs12 = pkcs12;
	attr->sa_pkcs12_len = len;
	return 0;
}

int
ar_svc_attr_set_tls(ar_svc_attr_t *attr, void *arg, 
		    ar_tls_setup_cb_t setup, ar_tls_verify_cb_t verify,
		    ar_tls_info_cb_t info)
{
	if (!attr) {
		return EINVAL;
	}

	attr->sa_tls_arg = arg;
	attr->sa_tls_setup_cb = setup;
	attr->sa_tls_verify_cb = verify;
	attr->sa_tls_info_cb = info;
	return 0;
}

int
ar_svc_attr_set_recvsize(ar_svc_attr_t *attr, int recvsize)
{
	if (!attr) {
		return EINVAL;
	}

	attr->sa_recvsz = recvsize;
	return 0;
}

int
ar_svc_attr_set_sendsize(ar_svc_attr_t *attr, int sendsize)
{
	if (!attr) {
		return EINVAL;
	}

	attr->sa_sendsz = sendsize;
	return 0;
}

int
ar_svc_attr_set_accept_cb(ar_svc_attr_t *attr, ar_svc_acceptcb_t cb, void *arg)
{
	if (!attr) {
		return EINVAL;
	}

	attr->sa_accept_cb = cb;
	attr->sa_accept_arg = arg;
	return 0;
}


int
ar_svc_attr_set_debug(ar_svc_attr_t *attr, FILE *fp, const char *prefix)
{
	if (!attr) {
		return EINVAL;
	}

	attr->sa_debug_file = fp;
	attr->sa_debug_prefix = prefix;
	return 0;
}

int
ar_svc_attr_set_max_connections(ar_svc_attr_t *attr, int max)
{

	if (!attr) {
		return EINVAL;
	}
	
	if (max < 1) {
		return EINVAL;
	}

	attr->sa_max_connections = max;
	return 0;
}

int
ar_svc_attr_set_error_cb(ar_svc_attr_t *attr, ar_svc_errorcb_t cb, 
			 void *arg)
{
	if (!attr) {
		return EINVAL;
	}

	attr->sa_error_cb = cb;
	attr->sa_error_arg = arg;
	return 0;
}

int
ar_svc_attr_destroy(ar_svc_attr_t *attr)
{
	if (!attr) {
		return EINVAL;
	}

	return 0;
}

void
ar_svc_destroy(ar_svc_xprt_t *xprt)
{
	if (!xprt) {
		return;
	}
	(*(xprt)->xp_ops->xp_destroy)(xprt);
}


bool_t
ar_svc_control_default(ar_svc_xprt_t *xprt, const u_int cmd, void *info)
{
	ar_ioep_t ioep;

	/* some control commands can get handling centrally: */
	switch (cmd) {
	case AR_SVCSET_DEBUG: {
		ar_xprt_debug_t *rxd;
		char *cp;

		rxd = (ar_xprt_debug_t *)info;
		if (!rxd) {
			return FALSE;
		}

		ioep = xprt->xp_ioep;
		if (!ioep) {
			return FALSE;
		}

		if (rxd->prefix) {
			cp = strdup(rxd->prefix);
			if (!cp) {
				return FALSE;
			}
		} else {
			cp = NULL;
		}

		ioep->iep_debug_file = rxd->fout;
		if (ioep->iep_debug_prefix) {
			free(ioep->iep_debug_prefix);
		}
		ioep->iep_debug_prefix = cp;
		return TRUE;
	}
	default:
		return FALSE;
	}
}


bool_t
ar_svc_control(ar_svc_xprt_t *xprt, const u_int cmd, void *info)
{
	if (!xprt) {
		return FALSE;
	}

	if (!xprt->xp_ops || !xprt->xp_ops->xp_control) {
		return FALSE;
	}

	return (*(xprt)->xp_ops->xp_control)(xprt, cmd, info);
}

void
ar_svc_set_user(ar_svc_xprt_t *xprt, void *arg)
{
	if (!xprt) {
		return;
	}

	xprt->xp_user = arg;
}

void *
ar_svc_get_user(ar_svc_xprt_t *xprt)
{
	if (!xprt) {
		return NULL;
	}

	return xprt->xp_user;
}

int
ar_svc_async(ar_svc_req_t *req, ar_svc_call_obj_t *scop)
{
	ar_svc_call_obj_t sco;

	if (!req || !scop) {
		return EINVAL;
	}

	/* request structure is embedded within the sco object.  Just
	 * fish it back out.
	 */
	sco = (ar_svc_call_obj_t)(((uint8_t *)req) - 
				  ar_offsetof(struct ar_svc_call_obj_s, 
					      sco_req));
	sco->sco_flags |= SCO_FLG_ASYNC;
	*scop = sco;
	return EOK;
}

int
ar_svc_async_get_resultptr(ar_svc_call_obj_t sco, void **argpp)
{
	if (!sco || !argpp) {
		return EINVAL;
	}

	if ((sco->sco_flags & SCO_FLG_ASYNC) == 0) {
		return EBUSY;
	}

	if ((sco->sco_flags & (SCO_FLG_DESTROY|SCO_FLG_HNDLR_DONE)) != 0) {
		return EINVAL;
	}

	if (!sco->sco_result) {
		return ENOENT;
	}

	*argpp = sco->sco_result;
	return EOK;
}

void
ar_svc_async_done(ar_svc_call_obj_t sco, bool_t result)
{
	const struct xp_ops *ops;
	arpc_msg_t *rply;
	ar_svc_xprt_t *sco_xp;
	ar_ioep_t ioep;
	int err;

	if (!sco) {
		return;
	}

	if ((sco->sco_flags & SCO_FLG_USRREF_DEC) != 0) {
		/* shouldn't be here, we have no valid reference */
		return;
	}

	sco_xp = sco->sco_xp;
	ops = sco_xp->xp_ops;

	if ((sco->sco_flags & SCO_FLG_ASYNC) == 0) {
		/* illegal, we are not in async mode */
		return;
	}

	if ((sco->sco_flags & SCO_FLG_HNDLR_DONE) != 0) {
		/* already done */
		return;
	}

	ioep = sco_xp->xp_ioep;
	if (sco->sco_flags & SCO_FLG_DESTROY || !ioep) {
		/* we've been destroyed asyncronously.  clean up. */
		(*ops->xp_sco_destroy)(sco_xp, sco);
		return;
	}

	if (sco->sco_state != SCO_STATE_ASYNC) {
		/* still in user's callback. Mark it done and
		 * handle it in the main path.
		 */
		sco->sco_flags |= SCO_FLG_HNDLR_DONE;
		return;
	}

	if (result <= 0 && sco->sco_err.re_status == ARPC_SUCCESS) {
		/* Result not generated and no error flagged for
		 * reply, abort handling and don't respond 
		 */

		/* release user refernce */
		if ((sco->sco_flags & SCO_FLG_USRREF_DEC) == 0) {
			sco->sco_flags |= SCO_FLG_USRREF_DEC;
			sco->sco_refcnt--;
		}
		/* destroy object */
		(*ops->xp_sco_destroy)(sco_xp, sco);
		/* done */
		return;
	}

	TAILQ_REMOVE(&ioep->iep_svc_async_calls, sco, sco_listent);

	/* call is done. */
	/* free up args */
	axdr_free(sco->sco_argsxdr, sco->sco_args);
	free(sco->sco_args);
	sco->sco_args = NULL;
	sco->sco_argsxdr = NULL;
	sco->sco_argslen = 0;

	/* release usr reference */
	sco->sco_flags |= SCO_FLG_USRREF_DEC;
	sco->sco_refcnt--;
	
	/* Setup reply object */
	rply = &sco->sco_reply;
	memset(rply, 0, sizeof(*rply));

	if (result > 0) {
		/* success */
		rply->arm_direction = AR_REPLY;
		rply->arm_xid = sco->sco_req.rq_xid;
		rply->arm_reply.arp_stat = AR_MSG_ACCEPTED; 
		rply->arm_acpted_rply.aar_verf = ioep->iep_verf;
		rply->arm_acpted_rply.aar_stat = AR_SUCCESS;
		rply->arm_acpted_rply.aar_results.where = sco->sco_result;
		rply->arm_acpted_rply.aar_results.proc = sco->sco_resultxdr;
	} else {
		/* sending error, result not required */
		axdr_free(sco->sco_resultxdr, sco->sco_result);
		free(sco->sco_result);
		sco->sco_result = NULL;

		svc_setup_err_reply(rply, sco->sco_req.rq_xid,
				    &ioep->iep_verf, &sco->sco_err);
	}

	sco->sco_flags |= SCO_FLG_HNDLR_DONE;

	ar_log_msg(ioep, rply, "sending async reply:");

	sco->sco_state = SCO_STATE_CALL;

	err = (*ops->xp_sco_reply)(sco_xp, sco);
	if (err != 0) {
		(*ops->xp_sco_destroy)(sco_xp, sco);
	}
}

arpc_addr_t *
ar_svc_getrpccaller(ar_svc_xprt_t *xprt)
{
	arpc_addr_t *addr;
	arpc_addr_t tbuf;
	struct sockaddr_storage ss;
	
	tbuf.buf = (char *)&ss;
	tbuf.len = sizeof(ss);
	tbuf.maxlen = sizeof(ss);
	
	if (!ar_svc_control(xprt, AR_SVCGET_REMOTE_ADDR, &tbuf)) {
		return NULL;
	}

	addr = malloc(sizeof(*addr));
	if (!addr) {
		return NULL;
	}

	addr->buf = malloc(tbuf.len);
	if (!addr->buf) {
		free(addr);
		return NULL;
	}
	memcpy(addr->buf, tbuf.buf, tbuf.len);
	addr->len = tbuf.len;
	addr->maxlen = tbuf.len;
	return addr;
}


void
ar_svcflgerr_decode(ar_svc_req_t *rqstp)
{
	if (!rqstp) {
		return;
	}

	rqstp->rq_err.re_status = ARPC_CANTDECODEARGS;
}

void
ar_svcflgerr_weakauth(ar_svc_req_t *rqstp)
{
	ar_svcflgerr_auth(rqstp, AR_AUTH_TOOWEAK);
}

void
ar_svcflgerr_noproc(ar_svc_req_t *rqstp)
{
	if (!rqstp) {
		return;
	}

	rqstp->rq_err.re_status = ARPC_PROCUNAVAIL;
}

void
ar_svcflgerr_progvers(ar_svc_req_t *rqstp, 
		      arpcvers_t low_vers, arpcvers_t high_vers)
{
	if (!rqstp) {
		return;
	}

	rqstp->rq_err.re_status = ARPC_PROGVERSMISMATCH;
	rqstp->rq_err.re_vers.low = low_vers;
	rqstp->rq_err.re_vers.high = high_vers;
}

void
ar_svcflgerr_auth(ar_svc_req_t *rqstp, ar_auth_stat_t why)
{
	if (!rqstp) {
		return;
	}
	
	rqstp->rq_err.re_status = ARPC_AUTHERROR;
	rqstp->rq_err.re_why = why;
}

void
ar_svcflgerr_noprog(ar_svc_req_t *rqstp)
{
	if (!rqstp) {
		return;
	}

	rqstp->rq_err.re_status = ARPC_PROGUNAVAIL;
}

void
ar_svcflgerr_systemerr(ar_svc_req_t *rqstp)
{
	if (!rqstp) {
		return;
	}
	rqstp->rq_err.re_status = ARPC_SYSTEMERROR;
}

void
ar_scoflgerr_decode(ar_svc_call_obj_t sco)
{
	if (!sco) {
		return;
	}

	sco->sco_err.re_status = ARPC_CANTDECODEARGS;
}

void
ar_scoflgerr_weakauth(ar_svc_call_obj_t sco)
{
	ar_scoflgerr_auth(sco, AR_AUTH_TOOWEAK);
}

void
ar_scoflgerr_noproc(ar_svc_call_obj_t sco)
{
	if (!sco) {
		return;
	}

	sco->sco_err.re_status = ARPC_PROCUNAVAIL;
}

void
ar_scoflgerr_progvers(ar_svc_call_obj_t sco, arpcvers_t low_vers,
		      arpcvers_t high_vers)
{
	if (!sco) {
		return;
	}

	sco->sco_err.re_status = ARPC_PROGVERSMISMATCH;
	sco->sco_err.re_vers.low = low_vers;
	sco->sco_err.re_vers.high = high_vers;
}

void
ar_scoflgerr_auth(ar_svc_call_obj_t sco, ar_auth_stat_t why)
{
	if (!sco) {
		return;
	}

	sco->sco_err.re_status = ARPC_AUTHERROR;
	sco->sco_err.re_why = why;
}

void
ar_scoflgerr_noprog(ar_svc_call_obj_t sco)
{
	if (!sco) {
		return;
	}

	sco->sco_err.re_status = ARPC_PROGUNAVAIL;
}

void
ar_scoflgerr_systemerr(ar_svc_call_obj_t sco)
{
	if (!sco) {
		return;
	}
	sco->sco_err.re_status = ARPC_SYSTEMERROR;
}

