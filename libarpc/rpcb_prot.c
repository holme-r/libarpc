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
 * Copyright (c) 1986-1991 by Sun Microsystems Inc. 
 */

/*
 * rpcb_prot.c
 * XDR routines for the rpcbinder version 3.
 *
 * Copyright (C) 1984, 1988, Sun Microsystems, Inc.
 */

#include "compat.h"

#include <libarpc/arpc.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>
#include <rpcb_prot.h>

axdr_ret_t
axdr_rpcb(axdr_state_t *xdrs, rpcb *objp)
{
	int		off;
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;
	rval = axdr_async_setup(xdrs, &axdr_rpcb, &cleanup,
	                       &state, 0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}
	switch (state) {
	case 0:
		rval = axdr_element(xdrs, ".r_prog", TRUE, 
				    (axdrproc_t)&axdr_u_int32_t, 
				    &objp->r_prog, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 1;
		/* fallthrough */
	case 1:
		rval = axdr_element(xdrs, ".r_vers", FALSE, 
				    (axdrproc_t)&axdr_u_int32_t, 
				    &objp->r_vers, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 2;
		/* fallthrough */
	case 2:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".r_netid",
						 FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_string(xdrs, &objp->r_netid, ~0);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 3;
		/* fallthrough */
	case 3:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".r_addr", 
						 FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_string(xdrs, &objp->r_addr, ~0);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 4;
		/* fallthrough */
	case 4:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".r_owner", 
						 FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_string(xdrs, &objp->r_owner, ~0);
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
	axdr_async_teardown(xdrs, &axdr_rpcb, state, cleanup, rval);
	return rval;
}

/*
 * rpcblist_ptr implements a linked list.  The RPCL definition from
 * rpcb_prot.x is:
 *
 * struct rpcblist {
 * 	rpcb		rpcb_map;
 *	struct rpcblist *rpcb_next;
 * };
 * typedef rpcblist *rpcblist_ptr;
 *
 * Recall that "pointers" in XDR are encoded as a boolean, indicating whether
 * there's any data behind the pointer, followed by the data (if any exists).
 * The boolean can be interpreted as ``more data follows me''; if FALSE then
 * nothing follows the boolean; if TRUE then the boolean is followed by an
 * actual struct rpcb, and another rpcblist_ptr (declared in RPCL as "struct
 * rpcblist *").
 *
 * This could be implemented via the xdr_pointer type, though this would
 * result in one recursive call per element in the list.  Rather than do that
 * we can ``unwind'' the recursion into a while loop and use xdr_reference to
 * serialize the rpcb elements.
 */
axdr_ret_t
axdr_rpcblist_ptr(axdr_state_t *xdrs, rpcblist_ptr *rp)
{
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		off;
	int		state = 0;
	int		idx;
	char 		buf[32];

	/*
	 * more_elements is pre-computed in case the direction is
	 * XDR_ENCODE or XDR_FREE.  more_elements is overwritten by
	 * xdr_bool when the direction is XDR_DECODE.
	 */
	bool_t more_elements;
	int freeing = (xdrs->x_op == AXDR_FREE);
	rpcblist_ptr next;
	rpcblist_ptr next_copy;
	bool_t	stringify = xdrs->x_op == AXDR_STRINGIFY;

	rval = axdr_async_setup(xdrs, &axdr_rpcblist_ptr, 
				&cleanup, &state, 0, NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	for (idx = 0; (idx + 1) < state; idx += 2) {
		more_elements = (bool_t)(*rp != NULL);
		if (!more_elements) {
			break;
		}
		rp = &((*rp)->rpcb_next);
	}

	if (stringify) {
		snprintf(buf, sizeof(buf), ".[%u]", state >> 1);
		rval = axdr_str_set_name(xdrs, buf, TRUE, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
	}
	
	next = NULL;
	rval = AXDR_DONE;
	for (;;) {
		more_elements = (bool_t)(*rp != NULL);
		if ((state & 1) != 1) {
			if (stringify) {
				snprintf(buf, sizeof(buf), ".[%u].continue", 
					 state >> 1);
				rval = axdr_str_set_name(xdrs, buf, 
							 FALSE, &off);
				if (rval != AXDR_DONE) {
					goto out;
				}
			}
			rval = axdr_bool(xdrs, &more_elements);
			if (rval != AXDR_DONE) {
				break;
			}
			state += 1;
			if (!more_elements) {
				break;	/* we are done */
			}
		}
		/*
		 * the unfortunate side effect of non-recursion is that in
		 * the case of freeing we must remember the next object
		 * before we free the current object ...
		 */
		if (freeing) {
			next = (*rp)->rpcb_next;
		}

		if (stringify) {
			snprintf(buf, sizeof(buf), ".[%u].rpcb", state >> 1);
			rval = axdr_str_set_name(xdrs, buf, FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}

		rval = axdr_reference(xdrs, (caddr_t *)rp, 
				      (u_int)sizeof(rpcblist), 
				      (axdrproc_t)axdr_rpcb);
		if (rval != AXDR_DONE) {
			break;
		}
		if (freeing) {
			next_copy = next;
			rp = &next_copy;
			/*
			 * Note that in the subsequent iteration, next_copy
			 * gets nulled out by the xdr_reference
			 * but next itself survives.
			 */
		} else {
			rp = &((*rp)->rpcb_next);
		}
		state += 1;
	}

	if (stringify && rval == AXDR_DONE) {
		rval = axdr_str_set_name(xdrs, NULL, FALSE, &off);
	}

out:
	axdr_async_teardown(xdrs, &axdr_rpcblist_ptr, state, cleanup, rval);
	return rval;
}

/*
 * xdr_rpcblist() is specified to take a RPCBLIST **, but is identical in
 * functionality to xdr_rpcblist_ptr().
 */
axdr_ret_t 
axdr_rpcblist(axdr_state_t *xdrs, RPCBLIST **rp)
{
	return axdr_rpcblist_ptr(xdrs, (rpcblist_ptr *)rp);
}


axdr_ret_t
axdr_rpcb_entry(axdr_state_t *xdrs, rpcb_entry *objp)
{
	int		off;
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;
	rval = axdr_async_setup(xdrs, &axdr_rpcb_entry, &cleanup,
	                       &state, 0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}
	switch (state) {
	case 0:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".r_maddr", TRUE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_string(xdrs, &objp->r_maddr, ~0);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 1;
		/* fallthrough */
	case 1:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".r_nc_netid", 
						 FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_string(xdrs, &objp->r_nc_netid, ~0);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 2;
		/* fallthrough */
	case 2:
		rval = axdr_element(xdrs, ".r_nc_semantics", FALSE, 
				    (axdrproc_t)&axdr_u_int, 
				    &objp->r_nc_semantics, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 3;
		/* fallthrough */
	case 3:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".r_nc_protofmly", 
						 FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_string(xdrs, &objp->r_nc_protofmly, ~0);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 4;
		/* fallthrough */
	case 4:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".r_nc_proto", 
						 FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_string(xdrs, &objp->r_nc_proto, ~0);
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
	axdr_async_teardown(xdrs, &axdr_rpcb_entry, state, cleanup, rval);
	return rval;
}


axdr_ret_t
axdr_rpcb_entry_list_ptr(axdr_state_t *xdrs, rpcb_entry_list_ptr *rp)
{
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;
	int		idx;
	/*
	 * more_elements is pre-computed in case the direction is
	 * XDR_ENCODE or XDR_FREE.  more_elements is overwritten by
	 * xdr_bool when the direction is XDR_DECODE.
	 */
	bool_t more_elements;
	int freeing = (xdrs->x_op == AXDR_FREE);
	rpcb_entry_list_ptr next;
	rpcb_entry_list_ptr next_copy;

	rval = axdr_async_setup(xdrs, &axdr_rpcb_entry_list_ptr, 
				&cleanup, &state, 0, NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	for (idx = 0; (idx + 1) < state; idx += 2) {
		more_elements = (bool_t)(*rp != NULL);
		if (!more_elements) {
			break;
		}
		rp = &((*rp)->rpcb_entry_next);
	}

	next = NULL;
	rval = AXDR_DONE;
	for (;;) {
		more_elements = (bool_t)(*rp != NULL);
		if ((state & 1) != 1) {
			rval = axdr_bool(xdrs, &more_elements);
			if (rval != AXDR_DONE) {
				break;
			}
			state += 1;

			if (!more_elements) {
				break;  /* we are done */
			}
		}
		/*
		 * the unfortunate side effect of non-recursion is that in
		 * the case of freeing we must remember the next object
		 * before we free the current object ...
		 */
		if (freeing) {
			next = (*rp)->rpcb_entry_next;
		}

		rval = axdr_reference(xdrs, (caddr_t *)rp, 
				      (u_int)sizeof(rpcb_entry_list), 
				      (axdrproc_t)axdr_rpcb_entry);
		if (rval != AXDR_DONE) {
			break;
		}
		if (freeing) {
			next_copy = next;
			rp = &next_copy;
			/*
			 * Note that in the subsequent iteration, next_copy
			 * gets nulled out by the xdr_reference
			 * but next itself survives.
			 */
		} else {
			rp = &((*rp)->rpcb_entry_next);
		}
		state += 1;
	}

	axdr_async_teardown(xdrs, &axdr_rpcb_entry_list_ptr, 
			    state, cleanup, rval);
	return rval;
}

/*
 * XDR remote call arguments
 * written for XDR_ENCODE direction only
 */
axdr_ret_t
axdr_rpcb_rmtcallargs(axdr_state_t *xdrs, struct rpcb_rmtcallargs *p)
{
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;
	uint32_t	len;
	struct r_rpcb_rmtcallargs *objp =
	    (struct r_rpcb_rmtcallargs *)(void *)p;
	int32_t *buf;

	rval = axdr_async_setup(xdrs, &axdr_rpcb_rmtcallargs,
				&cleanup, &state, 0, NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	switch (state) {
	case 0:
		buf = axdr_inline(xdrs, 3 * BYTES_PER_XDR_UNIT);
		if (buf != NULL) {
			IAXDR_PUT_U_INT32(buf, objp->prog);
			IAXDR_PUT_U_INT32(buf, objp->vers);
			IAXDR_PUT_U_INT32(buf, objp->proc);
			state = 4;
			goto header_done;
		} else {
			state = 1;
		}
		/* fallthrough */
	case 1:
		rval = axdr_u_int32_t(xdrs, &objp->prog);
		if (rval != AXDR_DONE) {
			break;
		}
		state = 2;
		/* fallthrough */
	case 2:
		rval = axdr_u_int32_t(xdrs, &objp->vers);
		if (rval != AXDR_DONE) {
			break;
		}
		state = 3;
		/* fallthrough */
	case 3:
		rval = axdr_u_int32_t(xdrs, &objp->proc);
		if (rval != AXDR_DONE) {
			break;
		}
		state = 4;
		/* fallthrough */
	case 4:
	header_done: 
		len = axdr_sizeof((axdrproc_t)objp->xdr_args, 
				  objp->args.args_val);
		objp->args.args_len = len;
		state = 5;
		/* fallthrough */
	case 5:
		rval = axdr_u_int(xdrs, &(objp->args.args_len));
		if (rval != AXDR_DONE) {
			break;
		}
		state = 6;
		/* fallthrough */
	case 6:
		rval = (*objp->xdr_args)(xdrs, objp->args.args_val);
		if (rval != AXDR_DONE) {
			break;
		}
		state = 7;
		break; /* done */
	default:
		rval = AXDR_ERROR;
		break;
	}

	axdr_async_teardown(xdrs, &axdr_rpcb_rmtcallargs, 
			    state, cleanup, rval);
	return rval;
}

/*
 * Results of the remote call
 */
axdr_ret_t
axdr_rpcb_rmtcallres(axdr_state_t *xdrs, rpcb_rmtcallres *objp)
{
	int		off;
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;
	rval = axdr_async_setup(xdrs, &axdr_rpcb_rmtcallres, &cleanup,
	                       &state, 0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}
	switch (state) {
	case 0:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".addr", TRUE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_string(xdrs, &objp->addr, ~0);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 1;
		/* fallthrough */
	case 1:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".results", 
						 FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_bytes(xdrs, (char **)&objp->results.results_val, 
				  (u_int *) &objp->results.results_len, ~0);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 2;
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
	axdr_async_teardown(xdrs, &axdr_rpcb_rmtcallres, state, cleanup, rval);
	return rval;
}

axdr_ret_t
axdr_arpc_addr_t(axdr_state_t *xdrs, arpc_addr_t *objp)
{
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;
	int		off;

	rval = axdr_async_setup(xdrs, &axdr_arpc_addr_t, &cleanup,
				&state, 0, NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	switch (state) {
	case 0:
		rval = axdr_element(xdrs, ".maxlen", TRUE, 
				    (axdrproc_t)&axdr_u_int32_t, 
				    &objp->maxlen, &off);
		if (rval != AXDR_DONE) {
			break;
		}
		state = 1;
		/* fallthrough */
	case 1:
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, ".buf", 
						 FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		rval = axdr_bytes(xdrs, (char **)&(objp->buf),
				  (u_int *)&(objp->len), objp->maxlen);
		if (rval != AXDR_DONE) {
			break;
		}
		if (xdrs->x_op == AXDR_STRINGIFY) {
			rval = axdr_str_set_name(xdrs, NULL, FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}
		state = 2;
		break; /* done */
	default:
		rval = AXDR_ERROR;
		break;
	}

out:
	axdr_async_teardown(xdrs, &axdr_arpc_addr_t, state, cleanup, rval);
	return rval;
}


