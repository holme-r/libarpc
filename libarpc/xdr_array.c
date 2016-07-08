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
 * xdr_array.c, Generic XDR routines impelmentation.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * These are the "non-trivial" xdr primitives used to serialize and
 * de-serialize arrays.  See xdr.h for more info on the interface to xdr.
 */

#include "compat.h"

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libarpc/arpc.h>
#include <libarpc/stack.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>

/**
 * XDR an array of arbitrary elements
 * *addrp is a pointer to the array, *sizep is the number of elements.
 * If addrp is NULL (*sizep * elsize) bytes are allocated.
 * elsize is the size (in bytes) of each element, and elproc is the
 * xdr procedure to call to handle each element of the array.
 *
 * @param xdrs
 * @param addrp - array pointer
 * @param sizep - number of elements 
 * @param maxsize - max numberof elements
 * @param elsize - size in bytes of each element
 * @param elproc - xdr routine to handle each element
 * @return
 */
axdr_ret_t
axdr_array(axdr_state_t *xdrs, caddr_t *addrp, u_int *sizep, u_int maxsize,
	   u_int elsize, axdrproc_t elproc)
{
	axdr_ret_t	rval;
	u_int 		i;
	caddr_t 	tmp;
	caddr_t 	target = *addrp;
	u_int 		c;  /* the actual element count */
	u_int 		nodesize;
	bool_t		cleanup;
	int		err;
	int		state = 0;
	int 		off;

	if (xdrs->x_op == AXDR_STRINGIFY) {
		char buf[32];

		c = *sizep;
		/*
		 * now we xdr each element of array
		 */
		for (i = 0; i < c; i++) {
			tmp = &target[elsize * i];
			snprintf(buf, sizeof(buf), "[%u]", i);
			rval = axdr_str_set_name(xdrs, buf, i == 0 ?
						TRUE : FALSE, &off);
			if (rval != AXDR_DONE) {
				return rval;
			}
			rval = (*elproc)(xdrs, tmp);
			if (rval != AXDR_DONE) {
				return rval;
			}
		}

		if (c > 0) {
			return axdr_str_set_name(xdrs, NULL, FALSE, &off);
		}
			
		return AXDR_DONE;
	}
		

	rval = axdr_async_setup(xdrs, &axdr_array, &cleanup, &state,
				   0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	switch (state) {
	case 0:
		/* like strings, arrays are really counted arrays */
		rval = axdr_u_int(xdrs, sizep);
		if (rval != AXDR_DONE) {
			goto out;
		}
		c = *sizep;
		if ((c > maxsize || UINT_MAX/elsize < c) &&
			(xdrs->x_op != AXDR_FREE)) {
			err = AXDR_ERROR;
			goto out;
		}
		nodesize = c * elsize;

		/*
		 * if we are deserializing, we may need to allocate an
		 * array.  We also save time by checking for a null
		 * array if we are freeing.
		 */
		rval = AXDR_WAITING;
		if (target == NULL) {
			switch (xdrs->x_op) {
			case AXDR_DECODE:
			case AXDR_DECODE_ASYNC:
				if (c == 0) {
					rval = AXDR_DONE;
					break;
				}
				*addrp = target = mem_alloc(nodesize);
				if (target == NULL) {
					warnx("axdr_array: out of memory");
					rval = AXDR_ERROR;
					goto out;
				}
				memset(target, 0, nodesize);
				break;
			case AXDR_FREE:
				rval = AXDR_DONE;
				break;
			case AXDR_ENCODE:
			case AXDR_ENCODE_ASYNC:
			case AXDR_STRINGIFY:
				break;
			}
			if (rval == AXDR_DONE) {
				break; /* finished */
			}
		}
		state = 1;
		/* fallthrough */
	default:
		c = *sizep;
		rval = AXDR_DONE;
		
		/*
		 * now we xdr each element of array
		 */
		for (i = state - 1; i < c; i++) {
			tmp = &target[elsize * i];
			rval = (*elproc)(xdrs, tmp);
			if (rval != AXDR_DONE) {
				goto out;
			}
			state = i+2;
		}

		if (i > c) {
			rval = AXDR_ERROR;
			goto out;
		}
		break;
	}

	/*
	 * the array may need freeing
	 */
	if (xdrs->x_op == AXDR_FREE) {
		mem_free(*addrp, c * elsize);
		*addrp = NULL;
	}

out:
	axdr_async_teardown(xdrs, &axdr_array, state, cleanup, rval);
	return rval;
}

/*
 * axdr_vector():
 *
 * XDR a fixed length array. Unlike variable-length arrays,
 * the storage of fixed length arrays is static and unfreeable.
 * > basep: base of the array
 * > size: size of the array
 * > elemsize: size of each element
 * > axdr_elem: routine to XDR each element
 */
axdr_ret_t
axdr_vector(axdr_state_t *xdrs, char *basep, u_int nelem, 
	    u_int elemsize, axdrproc_t axdr_elem)
{
	axdr_ret_t	rval;
	u_int		i;
	bool_t		cleanup;
	char		*elptr;
	int		state = 0;
	int		off;

	if (xdrs->x_op == AXDR_STRINGIFY) {
		char buf[32];

		/*
		 * now we xdr each element of array
		 */
		for (i = 0; i < nelem; i++) {
			elptr = &basep[elemsize * i];
			snprintf(buf, sizeof(buf), "[%u]", i);
			rval = axdr_str_set_name(xdrs, buf, i == 0 ? 
						TRUE : FALSE, &off);
			if (rval != AXDR_DONE) {
				return rval;
			}
			rval = (*axdr_elem)(xdrs, elptr);
			if (rval != AXDR_DONE) {
				return rval;
			}
		}

		if (nelem > 0) {
			return axdr_str_set_name(xdrs, NULL, FALSE, &off);
		}

		return AXDR_DONE;
	}


	rval = axdr_async_setup(xdrs, &axdr_vector, &cleanup, &state,
			       0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	for (i = state; i < nelem; i++) {
		elptr = &basep[i * elemsize];
		rval = (*axdr_elem)(xdrs, elptr);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = i+1;
	}

	if (i > nelem) {
		rval = AXDR_ERROR;
		goto out;
	}

out:
	axdr_async_teardown(xdrs, &axdr_vector, state, cleanup, rval);
	return rval;
}
