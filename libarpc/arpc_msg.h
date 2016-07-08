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
 * rpc_msg.h
 * rpc message definition
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */
#ifndef _LIBARPC_ARPC_MSG_H
#define _LIBARPC_ARPC_MSG_H

#define ARPC_MSG_VERSION	((u_int32_t) 2)
#define ARPC_SERVICE_PORT	((u_short) 2048)

/*
 * Bottom up definition of an rpc message.
 * NOTE: call and reply use the same overall stuct but
 * different parts of unions within it.
 */

typedef enum ar_msg_type_e {
	AR_CALL=0,
	AR_REPLY=1
} ar_msg_type_t;

typedef enum ar_reply_stat_e {
	AR_MSG_ACCEPTED=0,
	AR_MSG_DENIED=1
} ar_reply_stat_t;

typedef enum ar_accept_stat_e {
	AR_SUCCESS=0,
	AR_PROG_UNAVAIL=1,
	AR_PROG_MISMATCH=2,
	AR_PROC_UNAVAIL=3,
	AR_GARBAGE_ARGS=4,
	AR_SYSTEM_ERR=5
} ar_accept_stat_t;

typedef enum ar_reject_stat_e {
	AR_RPC_MISMATCH=0,
	AR_AUTH_ERROR=1
} ar_reject_stat_t;

/*
 * Reply part of an rpc exchange
 */

/*
 * Reply to an rpc request that was accepted by the server.
 * Note: there could be an error even though the request was
 * accepted.
 */
typedef struct ar_accepted_reply_s {
	ar_opaque_auth_t	aar_verf;
	ar_accept_stat_t	aar_stat;
	union {
		struct {
			arpcvers_t low;
			arpcvers_t high;
		} AAR_versions;
		struct {
			caddr_t	where;
			axdrproc_t proc;
		} AAR_results;
		/* and many other null cases */
	} ru;
#define	aar_results	ru.AAR_results
#define	aar_vers	ru.AAR_versions
} ar_accepted_reply_t;

/*
 * Reply to an rpc request that was rejected by the server.
 */
typedef struct ar_rejected_reply_s {
	ar_reject_stat_t	arj_stat;
	union {
		struct {
			arpcvers_t low;
			arpcvers_t high;
		} ARJ_versions;
		ar_auth_stat_t ARJ_why;  /* why authentication did not work */
	} ru;
#define	arj_vers	ru.ARJ_versions
#define	arj_why		ru.ARJ_why
} ar_rejected_reply_t;

/*
 * Body of a reply to an rpc request.
 */
typedef struct ar_reply_body_s {
	ar_reply_stat_t arp_stat;
	union {
		ar_accepted_reply_t ARP_ar;
		ar_rejected_reply_t ARP_dr;
	} ru;
#define	arp_acpt	ru.ARP_ar
#define	arp_rjct	ru.ARP_dr
} ar_reply_body_t;

/*
 * Body of an rpc request call.
 */
typedef struct ar_call_body_s {
	arpcvers_t acb_rpcvers;	/* must be equal to two */
	arpcprog_t acb_prog;
	arpcvers_t acb_vers;
	arpcproc_t acb_proc;
	ar_opaque_auth_t acb_cred;
	ar_opaque_auth_t acb_verf; /* protocol specific - provided by client */
	caddr_t acb_body_where;
	axdrproc_t acb_body_proc;   /* message specific */
} ar_call_body_t;

/*
 * The rpc message
 */
typedef struct arpc_msg_s {
	u_int32_t		arm_xid;
	ar_msg_type_t		arm_direction;
	union {
		ar_call_body_t ARM_cmb;
		ar_reply_body_t ARM_rmb;
	} ru;
#define	arm_call	ru.ARM_cmb
#define	arm_reply	ru.ARM_rmb
} arpc_msg_t;
#define	arm_acpted_rply	ru.ARM_rmb.ru.ARP_ar
#define	arm_rjcted_rply	ru.ARM_rmb.ru.ARP_dr

__BEGIN_DECLS
/*
 * XDR routine to handle a rpc msg (any type)
 * xdr_msg(xdrs, rmsg)
 * 	XDR *xdrs;
 * 	struct rpc_msg *rmsg;
 */
extern axdr_ret_t	axdr_msg(axdr_state_t *, arpc_msg_t *);

/*
 * XDR routine to handle an accepted rpc reply.
 * xdr_accepted_reply(xdrs, rej)
 * 	XDR *xdrs;
 * 	struct accepted_reply *rej;
 */
extern axdr_ret_t	axdr_accepted_reply(axdr_state_t *, 
					    ar_accepted_reply_t *);

/*
 * XDR routine to handle a rejected rpc reply.
 * xdr_rejected_reply(xdrs, rej)
 * 	XDR *xdrs;
 * 	struct rejected_reply *rej;
 */
extern axdr_ret_t	axdr_rejected_reply(axdr_state_t *, 
					    ar_rejected_reply_t *);

/*
 * Fills in the error part of a reply message.
 * _seterr_reply(msg, error)
 * 	arpc_msg_t *msg;
 * 	arpc_err_t *error;
 */
extern void	ar_seterr_reply(arpc_msg_t *, arpc_err_t *);
__END_DECLS

#endif /* !_LIBARPC_ARPC_MSG_H */
