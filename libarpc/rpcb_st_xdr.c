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
 * Copyright 1991 Sun Microsystems, Inc.
 * rpcb_stat_xdr.c
 */

/*
 * This file was generated from rpcb_prot.x, but includes only those
 * routines used with the rpcbind stats facility.
 */

#include "compat.h"

#include <libarpc/arpc.h>
#include "rpcb_prot.h"

/* Link list of all the stats about getport and getaddr */
axdr_ret_t
axdr_rpcbs_addrlist(axdr_state_t *xdrs, rpcbs_addrlist *objp)
{
	int		off;
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;
	rval = axdr_async_setup(xdrs, &axdr_rpcbs_addrlist, &cleanup,
	                       &state, 0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}
	switch (state) {
	case 0:
		rval = axdr_element(xdrs, ".prog", TRUE, 
				    (axdrproc_t)&axdr_u_int32_t, 
				    &objp->prog, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 1;
		/* fallthrough */
	case 1:
		rval = axdr_element(xdrs, ".vers", FALSE, 
				    (axdrproc_t)&axdr_u_int32_t, 
				    &objp->vers, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 2;
		/* fallthrough */
	case 2:
		rval = axdr_element(xdrs, ".success", FALSE, 
				    (axdrproc_t)&axdr_int, &objp->success, 
				    &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 3;
		/* fallthrough */
	case 3:
		rval = axdr_element(xdrs, ".failure", FALSE, 
				    (axdrproc_t)&axdr_int,
				    &objp->failure, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 4;
		/* fallthrough */
	case 4:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".netid", FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_string(xdrs, &objp->netid, ~0);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 5;
		/* fallthrough */
	case 5:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".next", FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_pointer(xdrs, (char **)&objp->next, 
				    sizeof (rpcbs_addrlist), 
				    (axdrproc_t) axdr_rpcbs_addrlist);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 6;
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, NULL, FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		break; /* done */
	default:
		rval = AXDR_ERROR;
	}
out:
	axdr_async_teardown(xdrs, &axdr_rpcbs_addrlist, state, cleanup, rval);
	return rval;
}

/* Link list of all the stats about rmtcall */
axdr_ret_t
axdr_rpcbs_rmtcalllist(axdr_state_t *xdrs, rpcbs_rmtcalllist *objp)
{
	int		off;
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;

	rval = axdr_async_setup(xdrs, &axdr_rpcbs_rmtcalllist, &cleanup,
	                       &state, 0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}
	switch (state) {
	case 0:
		rval = axdr_element(xdrs, ".prog", TRUE,
				    (axdrproc_t)&axdr_u_int32_t, 
				    &objp->prog, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 1;
		/* fallthrough */
	case 1:
		rval = axdr_element(xdrs, ".vers", FALSE, 
				    (axdrproc_t)&axdr_u_int32_t, 
				    &objp->vers, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 2;
		/* fallthrough */
	case 2:
		rval = axdr_element(xdrs, ".proc", FALSE, 
				    (axdrproc_t)&axdr_u_int32_t, 
				    &objp->proc, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 3;
		/* fallthrough */
	case 3:
		rval = axdr_element(xdrs, ".success", FALSE, 
				    (axdrproc_t)&axdr_int, &objp->success,
				    &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 4;
		/* fallthrough */
	case 4:
		rval = axdr_element(xdrs, ".failure", FALSE, 
				    (axdrproc_t)&axdr_int, 
				    &objp->failure, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 5;
		/* fallthrough */
	case 5:
		rval = axdr_element(xdrs, ".indirect", FALSE, 
				    (axdrproc_t)&axdr_int, 
				    &objp->indirect, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 6;
		/* fallthrough */
	case 6:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".netid", FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_string(xdrs, &objp->netid, ~0);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 7;
		/* fallthrough */
	case 7:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".next", FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_pointer(xdrs, (char **)&objp->next,
				    sizeof (rpcbs_rmtcalllist), 
				    (axdrproc_t) axdr_rpcbs_rmtcalllist);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 8;
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, NULL, FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		break; /* done */
	default:
		rval = AXDR_ERROR;
	}
out:
	axdr_async_teardown(xdrs, &axdr_rpcbs_rmtcalllist, state,
			    cleanup, rval);
	return rval;
}


axdr_ret_t
axdr_rpcbs_proc(axdr_state_t *xdrs, rpcbs_proc objp)
{
	return (axdr_vector(xdrs, (char *)objp, RPCBSTAT_HIGHPROC,
		sizeof (int), (axdrproc_t) axdr_int));
}

axdr_ret_t
axdr_rpcbs_addrlist_ptr(axdr_state_t *xdrs, rpcbs_addrlist_ptr *objp)
{
	return (axdr_pointer(xdrs, (char **)objp, 
			     sizeof (rpcbs_addrlist), 
			     (axdrproc_t) axdr_rpcbs_addrlist));
}

axdr_ret_t
axdr_rpcbs_rmtcalllist_ptr(axdr_state_t *xdrs, rpcbs_rmtcalllist_ptr *objp)
{
	return (axdr_pointer(xdrs, (char **)objp, 
			     sizeof (rpcbs_rmtcalllist), 
			     (axdrproc_t) axdr_rpcbs_rmtcalllist));
}

axdr_ret_t
axdr_rpcb_stat(axdr_state_t *xdrs, rpcb_stat *objp)
{
	int		off;
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;
	rval = axdr_async_setup(xdrs, &axdr_rpcb_stat, &cleanup,
	                       &state, 0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}
	switch (state) {
	case 0:
		rval = axdr_element(xdrs, ".info", TRUE, 
				    (axdrproc_t)&axdr_rpcbs_proc, 
				    objp->info, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 1;
		/* fallthrough */
	case 1:
		rval = axdr_element(xdrs, ".setinfo", FALSE,
				    (axdrproc_t)&axdr_int,
				    &objp->setinfo, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 2;
		/* fallthrough */
	case 2:
		rval = axdr_element(xdrs, ".unsetinfo", FALSE,
				    (axdrproc_t)&axdr_int,
				    &objp->unsetinfo, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 3;
		/* fallthrough */
	case 3:
		rval = axdr_element(xdrs, ".addrinfo", FALSE,
				    (axdrproc_t)&axdr_rpcbs_addrlist_ptr,
				    &objp->addrinfo, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 4;
		/* fallthrough */
	case 4:
		rval = axdr_element(xdrs, ".rmtinfo", FALSE,
				    (axdrproc_t)&axdr_rpcbs_rmtcalllist_ptr,
				    &objp->rmtinfo, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 5;
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, NULL, FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		break; /* done */
	default:
		rval = AXDR_ERROR;
	}
out:
	axdr_async_teardown(xdrs, &axdr_rpcb_stat, state, cleanup, rval);
	return rval;
}

/*
 * One rpcb_stat structure is returned for each version of rpcbind
 * being monitored.
 */
axdr_ret_t
axdr_rpcb_stat_byvers(axdr_state_t *xdrs, rpcb_stat_byvers objp)
{
	return (axdr_vector(xdrs, (char *)objp, RPCBVERS_STAT,
			    sizeof (rpcb_stat), (axdrproc_t) axdr_rpcb_stat));
}
