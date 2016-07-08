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
 * rpc_prot.c
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * This set of routines implements the rpc message definition,
 * its serializer and some common rpc utility routines.
 * The routines are meant for various implementations of rpc -
 * they are NOT for the rpc client or rpc service implementations!
 * Because authentication stuff is easy and is part of rpc, the opaque
 * routines are also in this program.
 */

#include "compat.h"

#include <sys/param.h>
#include <assert.h>
#include <libarpc/stack.h>
#include <libarpc/arpc.h>

static void accepted(ar_accept_stat_t, arpc_err_t *);
static void rejected(ar_reject_stat_t, arpc_err_t *);

axdr_ret_t
axdr_msg_type(axdr_state_t *xdrs, ar_msg_type_t *type)
{
	if (xdrs->x_op == AXDR_STRINGIFY) {
		const char *val;
		switch (*type) {
		case AR_CALL:
			val = "CALL";
			break;
		case AR_REPLY:
			val = "REPLY";
			break;
		default:
			val = NULL;
			break;
		}
		if (val) {
			return axdr_str_add_value(xdrs, val);
		}
	}

	return (axdr_enum(xdrs, (enum_t *)type));
}

axdr_ret_t
axdr_accept_stat(axdr_state_t *xdrs, ar_accept_stat_t *stat)
{
	if (xdrs->x_op == AXDR_STRINGIFY) {
		const char *val;
		switch (*stat) {
		case AR_SUCCESS:
			val = "SUCCESS";
			break;
		case AR_PROG_UNAVAIL:
			val = "PROG_UNAVAIL";
			break;
		case AR_PROG_MISMATCH:
			val = "PROG_MISMATCH";
			break;
		case AR_PROC_UNAVAIL:
			val = "PROC_UNAVAIL";
			break;
		case AR_GARBAGE_ARGS:
			val = "GARBAGE_ARGS";
			break;
		case AR_SYSTEM_ERR:
			val = "SYSTEM_ERR";
			break;
		default:
			val = NULL;
			break;
		}
		if (val) {
			return axdr_str_add_value(xdrs, val);
		}
	}

	return (axdr_enum(xdrs, (enum_t *)stat));
}


axdr_ret_t
axdr_reject_stat(axdr_state_t *xdrs, ar_reject_stat_t *stat)
{
	if (xdrs->x_op == AXDR_STRINGIFY) {
		const char *val;
		switch (*stat) {
		case AR_RPC_MISMATCH:
			val = "RPC_MISMATCH";
			break;
		case AR_AUTH_ERROR:
			val = "AUTH_ERROR";
			break;
		default:
			val = NULL;
			break;
		}
		if (val) {
			return axdr_str_add_value(xdrs, val);
		}
	}

	return (axdr_enum(xdrs, (enum_t *)stat));
}


axdr_ret_t
axdr_auth_stat(axdr_state_t *xdrs, ar_auth_stat_t *stat)
{
	if (xdrs->x_op == AXDR_STRINGIFY) {
		const char *val;
		switch (*stat) {
		case AR_AUTH_OK:
			val = "AUTH_OK";
			break;
		case AR_AUTH_BADCRED:
			val = "AUTH_BADCRED";
			break;
		case AR_AUTH_REJECTEDCRED:
			val = "AUTH_REJECTEDCRED";
			break;
		case AR_AUTH_BADVERF:
			val = "AUTH_BADVERF";
			break;
		case AR_AUTH_REJECTEDVERF:
			val = "AUTH_REJECTEDVERF";
			break;
		case AR_AUTH_TOOWEAK:
			val = "AUTH_TOOWEAK";
			break;
		case AR_AUTH_INVALIDRESP:
			val = "AUTH_INVALIDRESP";
			break;
		case AR_AUTH_FAILED:
			val = "AUTH_FAILED";
			break;
		case AR_AUTH_KERB_GENERIC :
			val = "AUTH_KERB_GENERIC";
			break;
		case AR_AUTH_TIMEEXPIRE :
			val = "AUTH_TIMEEXPIRE";
			break;
		case AR_AUTH_TKT_FILE :
			val = "AUTH_TKT_FILE";
			break;
		case AR_AUTH_DECODE :
			val = "AUTH_DECODE";
			break;
		case AR_AUTH_NET_ADDR :
			val = "AUTH_NET_ADDR";
			break;
		default:
			val = NULL;
			break;
		}
		if (val) {
			return axdr_str_add_value(xdrs, val);
		}
	}

	return (axdr_enum(xdrs, (enum_t *)stat));
}


/* * * * * * * * * * * * * * XDR Authentication * * * * * * * * * * * */

/*
 * XDR an opaque authentication struct
 * (see auth.h)
 */
axdr_ret_t
axdr_opaque_auth(axdr_state_t *xdrs, ar_opaque_auth_t *ap)
{
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;

	if (!xdrs || !ap) {
		return AXDR_ERROR;
	}

	if (xdrs->x_op == AXDR_STRINGIFY &&
	    ap->oa_flavor == AR_AUTH_NONE) {
		/* don't bother adding any info if it's NULL/NONE auth */
		return AXDR_DONE;
	}

	rval = axdr_async_setup(xdrs, &axdr_opaque_auth, &cleanup, &state,
			       0, NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	switch (state) {
	case 0:
		rval = axdr_enum(xdrs, &(ap->oa_flavor));
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 1;
		/* fallthrough */
	case 1:
		rval = axdr_bytes(xdrs, &ap->oa_base, 
				 &ap->oa_length, AR_MAX_AUTH_BYTES);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 2;
		break; /* done */
	default:
		return AXDR_ERROR;
	}

	axdr_async_teardown(xdrs, &axdr_opaque_auth, state, cleanup, rval);
	return rval;
}


/*
 * XDR a DES block
 */
axdr_ret_t
axdr_des_block(axdr_state_t *xdrs, ar_des_block_t *blkp)
{
	if (!xdrs || !blkp) {
		return AXDR_ERROR;
	}

	return (axdr_opaque(xdrs, (caddr_t)(void *)blkp,
			    sizeof(ar_des_block_t)));
}

/* * * * * * * * * * * * * * XDR RPC MESSAGE * * * * * * * * * * * * * * * */

/*
 * XDR the MSG_ACCEPTED part of a reply message union
 */
axdr_ret_t 
axdr_accepted_reply(axdr_state_t *xdrs, ar_accepted_reply_t *ar)
{
	axdr_ret_t	rval;
	bool_t		cleanup;
	axdrproc_t	proc;
	int		state = 0; 
	int		off;

	if (!xdrs || !ar) {
		return AXDR_ERROR;
	}

	rval = axdr_async_setup(xdrs, &axdr_accepted_reply, &cleanup, &state,
			       0, NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	/* personalized union, rather than calling axdr_union */
	switch (state) {
	case 0:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".verf", 
						 TRUE, &off);
			if (rval != AXDR_DONE) {
				return rval;
			}
		}

		rval = axdr_opaque_auth(xdrs, &(ar->aar_verf));
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 1;
		/* fallthrough */
	case 1:
		rval = axdr_element(xdrs, ".stat", FALSE, 
				    (axdrproc_t)&axdr_accept_stat, 
				    &(ar->aar_stat), &off);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}

		state = 2;
		/* fallthrough */
	case 2:
		switch (ar->aar_stat) {
		case AR_SUCCESS:
			proc = ar->aar_results.proc;
			if (proc) {
				if (xdrs->x_op == AXDR_STRINGIFY) {
					rval = axdr_str_set_name(xdrs, NULL,
								FALSE, &off);
					if (rval != AXDR_DONE) {
						return rval;
					}
				}
				rval = (*proc)(xdrs, ar->aar_results.where);
			} else {
				rval = AXDR_DONE;
			}
			break;
		case AR_PROG_MISMATCH:
			state = 3;
			goto mismatch;

		case AR_GARBAGE_ARGS:
		case AR_SYSTEM_ERR:
		case AR_PROC_UNAVAIL:
		case AR_PROG_UNAVAIL:
			rval = AXDR_DONE;
			break;
		default:
			return AXDR_ERROR;
		}

		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}

		state = 5;
		break; /* done */
	case 3:
	mismatch:
		rval = axdr_element(xdrs, ".low_ver", FALSE,
				   (axdrproc_t)&axdr_u_int32_t,
				   &(ar->aar_vers.low), &off);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 4;
		/* fallthrough */
	case 4:
		rval = axdr_element(xdrs, ".high_ver", FALSE,
				   (axdrproc_t)&axdr_u_int32_t,
				   &(ar->aar_vers.high), &off);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 5;
		break; /* done */
	default:
		return AXDR_ERROR;
	}

	if (rval == AXDR_DONE && xdrs->x_op == AXDR_STRINGIFY) {
		rval = axdr_str_set_name(xdrs, NULL, FALSE, &off);
		if (rval != AXDR_DONE) {
			return rval;
		}
	}

	axdr_async_teardown(xdrs, &axdr_accepted_reply, state, cleanup, rval);
	return rval;
}

/*
 * XDR the MSG_DENIED part of a reply message union
 */
axdr_ret_t
axdr_rejected_reply(axdr_state_t *xdrs, ar_rejected_reply_t *rr)
{
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;
	int		off;

	if (!xdrs || !rr) {
		return AXDR_ERROR;
	}

	rval = axdr_async_setup(xdrs, &axdr_rejected_reply, &cleanup, &state,
			       0, NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	/* personalized union, rather than calling axdr_union */
	switch (state) {
	case 0:
		rval = axdr_element(xdrs, ".stat", TRUE,
				   (axdrproc_t)&axdr_reject_stat, 
				   &(rr->arj_stat), &off);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 1;
		/* fallthrough */
	case 1:
	case 2:
		switch (rr->arj_stat) {
		case AR_RPC_MISMATCH:
			switch (state) {
			case 1:
				rval = axdr_element(xdrs, ".low_ver", FALSE, 
						   (axdrproc_t)&axdr_u_int32_t,
						   &(rr->arj_vers.low), &off);
				if (rval == AXDR_WAITING) {
					break;
				}
				if (rval != AXDR_DONE) {
					return rval;
				}
				state = 2;
				/* fallthrough */
			case 2:
				rval = axdr_element(xdrs, ".high_ver", FALSE, 
						   (axdrproc_t)&axdr_u_int32_t,
						   &(rr->arj_vers.high), &off);
				break;
			default:
				return AXDR_ERROR;
			}
			break;
		case AR_AUTH_ERROR:
			rval = axdr_element(xdrs, ".auth_why", FALSE, 
					   (axdrproc_t)&axdr_auth_stat,
					   &(rr->arj_why), &off);
			break;
		default:
			return AXDR_ERROR;
		}
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 3;

		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, NULL, FALSE, &off);
		}
			
		break; /* done */
	default:
		return AXDR_ERROR;
	}

	axdr_async_teardown(xdrs, &axdr_rejected_reply, state, cleanup, rval);
	return rval;
}


static const struct axdr_discrim reply_dscrm[3] = {
	{ AR_MSG_ACCEPTED, (axdrproc_t)axdr_accepted_reply, "ret"},
	{ AR_MSG_DENIED, (axdrproc_t)axdr_rejected_reply, "denied"},
	{ __dontcare__, NULL_axdrproc_t } };

/*
 * XDR a general message
 */
axdr_ret_t
axdr_msg(axdr_state_t *xdrs, arpc_msg_t *msg)
{
	axdr_ret_t 	rval;
	axdrproc_t	proc;
	bool_t		cleanup;
	int		state = 0;
	int		nstate;
	int 		off;

	if (!xdrs || !msg) {
		return AXDR_ERROR;
	}

	rval = axdr_async_setup(xdrs, &axdr_msg, &cleanup, &state,
			       0, NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	switch (state) {
	case 0:
		rval = axdr_element(xdrs, ".xid", TRUE, 
				   (axdrproc_t)&axdr_u_int32_t, &(msg->arm_xid),
				   &off);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 1;
		/* fallthrough */
	case 1:
		rval = axdr_element(xdrs, ".dir", FALSE, 
				   (axdrproc_t)&axdr_msg_type,
				   &(msg->arm_direction), &off);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		switch (msg->arm_direction) {
		case AR_CALL:
		case AR_REPLY:
			break;
		default:
			return AXDR_ERROR;
		}
		state = 2;
		/* fallthrough */
	case 2:
		switch (msg->arm_direction) {
		case AR_CALL:
			rval = axdr_element(xdrs, ".rpcver", FALSE,
					   (axdrproc_t)&axdr_u_int32_t,
					   &(msg->arm_call.acb_rpcvers), &off);
			nstate = 3;
			break;
		case AR_REPLY:
			if (xdrs->x_op == AXDR_STRINGIFY) {
				rval = axdr_str_set_name(xdrs, NULL, 
							FALSE, &off);
				if (rval != AXDR_DONE) {
					return rval;
				}
			}					
			rval = axdr_union(xdrs, 
					  (enum_t *)&(msg->arm_reply.arp_stat),
					  (caddr_t)&(msg->arm_reply.ru),
					  reply_dscrm, NULL_axdrproc_t);
			nstate = 8;
			break;
		default:
			rval = AXDR_ERROR;
			nstate = 8;
			break;
		}
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = nstate;
		if (nstate == 8) {
			break; /* done */
		}
		/* fallthrough */
	case 3:
		/* call operation */
		if (msg->arm_call.acb_rpcvers != ARPC_MSG_VERSION) {
			return AXDR_ERROR;
		}

		rval = axdr_element(xdrs, ".prog", FALSE,
				   (axdrproc_t)&axdr_u_int32_t,
				   &(msg->arm_call.acb_prog), &off);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 4;
		/* fallthrough */
	case 4:
		rval = axdr_element(xdrs, ".ver", FALSE,
				   (axdrproc_t)&axdr_u_int32_t,
				   &(msg->arm_call.acb_vers), &off);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 5;
		/* fallthrough */
	case 5:
		rval = axdr_element(xdrs, ".procedure", FALSE,
				   (axdrproc_t)&axdr_u_int32_t,
				   &(msg->arm_call.acb_proc), &off);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 6;
		/* fallthrough */
	case 6:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".cred", 
						 FALSE, &off);
			if (rval != AXDR_DONE) {
				return rval;
			}
		}

		rval = axdr_opaque_auth(xdrs, &(msg->arm_call.acb_cred));
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 7;
		/* fallthrough */
	case 7:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".verf", 
						FALSE, &off);
			if (rval != AXDR_DONE) {
				return rval;
			}
		}

		rval = axdr_opaque_auth(xdrs, &(msg->arm_call.acb_verf));
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		if (msg->arm_call.acb_body_proc) {
			state = 8;
		} else {
			state = 9;
			break; /* done */
		}
		/* fallthrough */
	case 8:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".body", 
						FALSE, &off);
			if (rval != AXDR_DONE) {
				return rval;
			}
		}
		proc = msg->arm_call.acb_body_proc;
		rval = (*proc)(xdrs, msg->arm_call.acb_body_where);
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		state = 9;

		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, NULL, FALSE, &off);
			if (rval != AXDR_DONE) {
				return rval;
			}
		}
		break; /* done */
	default:
		return AXDR_ERROR;
	}

	axdr_async_teardown(xdrs, &axdr_msg, state, cleanup, rval);
	return rval;
}

/* ************************** Client utility routine ************* */

static void
accepted(ar_accept_stat_t acpt_stat, arpc_err_t *error)
{

	assert(error != NULL);

	switch (acpt_stat) {

	case AR_PROG_UNAVAIL:
		error->re_status = ARPC_PROGUNAVAIL;
		return;

	case AR_PROG_MISMATCH:
		error->re_status = ARPC_PROGVERSMISMATCH;
		return;

	case AR_PROC_UNAVAIL:
		error->re_status = ARPC_PROCUNAVAIL;
		return;

	case AR_GARBAGE_ARGS:
		error->re_status = ARPC_CANTDECODEARGS;
		return;

	case AR_SYSTEM_ERR:
		error->re_status = ARPC_SYSTEMERROR;
		return;

	case AR_SUCCESS:
		error->re_status = ARPC_SUCCESS;
		return;
	}
	/* NOTREACHED */
	/* something's wrong, but we don't know what ... */
	error->re_status = ARPC_FAILED;
	error->re_lb.s1 = (int32_t)AR_MSG_ACCEPTED;
	error->re_lb.s2 = (int32_t)acpt_stat;
}

static void 
rejected(ar_reject_stat_t rjct_stat, arpc_err_t *error)
{

	assert(error != NULL);

	switch (rjct_stat) {
	case AR_RPC_MISMATCH:
		error->re_status = ARPC_VERSMISMATCH;
		return;

	case AR_AUTH_ERROR:
		error->re_status = ARPC_AUTHERROR;
		return;
	}
	/* something's wrong, but we don't know what ... */
	/* NOTREACHED */
	error->re_status = ARPC_FAILED;
	error->re_lb.s1 = (int32_t)AR_MSG_DENIED;
	error->re_lb.s2 = (int32_t)rjct_stat;
}

/*
 * given a reply message, fills in the error
 */
void
ar_seterr_reply(arpc_msg_t *msg, arpc_err_t *error)
{

	assert(msg != NULL);
	assert(error != NULL);

	/* optimized for normal, SUCCESSful case */
	switch (msg->arm_reply.arp_stat) {
	case AR_MSG_ACCEPTED:
		if (msg->arm_acpted_rply.aar_stat == AR_SUCCESS) {
			error->re_status = ARPC_SUCCESS;
			return;
		}
		accepted(msg->arm_acpted_rply.aar_stat, error);
		break;

	case AR_MSG_DENIED:
		rejected(msg->arm_rjcted_rply.arj_stat, error);
		break;

	default:
		error->re_status = ARPC_FAILED;
		error->re_lb.s1 = (int32_t)(msg->arm_reply.arp_stat);
		break;
	}
	switch (error->re_status) {
	case ARPC_VERSMISMATCH:
		error->re_vers.low = msg->arm_rjcted_rply.arj_vers.low;
		error->re_vers.high = msg->arm_rjcted_rply.arj_vers.high;
		break;

	case ARPC_AUTHERROR:
		error->re_why = msg->arm_rjcted_rply.arj_why;
		break;

	case ARPC_PROGVERSMISMATCH:
		error->re_vers.low = msg->arm_acpted_rply.aar_vers.low;
		error->re_vers.high = msg->arm_acpted_rply.aar_vers.high;
		break;
	case ARPC_FAILED:
	case ARPC_SUCCESS:
	case ARPC_PROGNOTREGISTERED:
	case ARPC_RPCBFAILURE:
	case ARPC_UNKNOWNPROTO:
	case ARPC_UNKNOWNHOST:
	case ARPC_SYSTEMERROR:
	case ARPC_CANTDECODEARGS:
	case ARPC_PROCUNAVAIL:
	case ARPC_PROGUNAVAIL:
	case ARPC_TIMEDOUT:
	case ARPC_CANTRECV:
	case ARPC_CANTSEND:
	case ARPC_CANTDECODERES:
	case ARPC_CANTENCODEARGS:
	default:
		break;
	}
}
