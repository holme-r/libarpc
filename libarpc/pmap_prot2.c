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
 * pmap_prot2.c
 * Protocol for the local binder service, or pmap.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#include "compat.h"

#include <assert.h>
#include <libarpc/arpc.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>
#include "pmap_prot.h"

/*
 * What is going on with linked lists? (!)
 * First recall the link list declaration from pmap_prot.h:
 *
 * struct pmaplist {
 *	struct pmap pml_map;
 *	struct pmaplist *pml_map;
 * };
 *
 * Compare that declaration with a corresponding xdr declaration that
 * is (a) pointer-less, and (b) recursive:
 *
 * typedef union switch (bool_t) {
 *
 *	case TRUE: struct {
 *		struct pmap;
 * 		pmaplist_t foo;
 *	};
 *
 *	case FALSE: struct {};
 * } pmaplist_t;
 *
 * Notice that the xdr declaration has no nxt pointer while
 * the C declaration has no bool_t variable.  The bool_t can be
 * interpreted as ``more data follows me''; if FALSE then nothing
 * follows this bool_t; if TRUE then the bool_t is followed by
 * an actual struct pmap, and then (recursively) by the
 * xdr union, pamplist_t.
 *
 * This could be implemented via the xdr_union primitive, though this
 * would cause a one recursive call per element in the list.  Rather than do
 * that we can ``unwind'' the recursion
 * into a while loop and do the union arms in-place.
 *
 * The head of the list is what the C programmer wishes to past around
 * the net, yet is the data that the pointer points to which is interesting;
 * this sounds like a job for xdr_reference!
 */
axdr_ret_t
axdr_ar_pmaplist(axdr_state_t *xdrs, ar_pmaplist_t **rp)
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
	int freeing;
	ar_pmaplist_t *next	= NULL; /* pacify gcc */
	ar_pmaplist_t *next_copy = NULL; /* pacify gcc */
	bool_t stringify;

	assert(xdrs != NULL);
	assert(rp != NULL);

	freeing = (xdrs->x_op == AXDR_FREE);
	stringify = xdrs->x_op == AXDR_STRINGIFY;

	rval = axdr_async_setup(xdrs, &axdr_ar_pmaplist, 
				&cleanup, &state, 0, NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	for (idx = 0; (idx + 1) < state; idx += 2) {
		more_elements = (bool_t)(*rp != NULL);
		if (!more_elements) {
			break;
		}
		rp = &((*rp)->pml_next);
	}


	if (stringify) {
		snprintf(buf, sizeof(buf), ".[%u]", state >> 1);
		rval = axdr_str_set_name(xdrs, buf, TRUE, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
	}
	
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
			next = (*rp)->pml_next;
		}

		if (stringify) {
			snprintf(buf, sizeof(buf), ".[%u].pmap", state >> 1);
			rval = axdr_str_set_name(xdrs, buf, FALSE, &off);
			if (rval != AXDR_DONE) {
				goto out;
			}
		}

		rval = axdr_reference(xdrs, (caddr_t *)rp, 
				      (u_int)sizeof(ar_pmaplist_t), 
				      (axdrproc_t)axdr_ar_pmap);
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
			rp = &((*rp)->pml_next);
		}
		state += 1;
	}

	if (stringify && rval == AXDR_DONE) {
		rval = axdr_str_set_name(xdrs, NULL, FALSE, &off);
	}
out:
	axdr_async_teardown(xdrs, &axdr_ar_pmaplist, state, cleanup, rval);
	return rval;
}


/*
 * xdr_pmaplist_ptr() is specified to take a PMAPLIST *, but is identical in
 * functionality to xdr_pmaplist().
 */
axdr_ret_t
axdr_ar_pmaplist_ptr(axdr_state_t *xdrs, ar_pmaplist_ptr *objp)
{
	return axdr_ar_pmaplist(xdrs, objp);
}
