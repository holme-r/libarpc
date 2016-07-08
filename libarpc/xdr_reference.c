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
 * xdr_reference.c, Generic XDR routines impelmentation.
 *
 * Copyright (C) 1987, Sun Microsystems, Inc.
 *
 * These are the "non-trivial" xdr primitives used to serialize and
 * de-serialize "pointers".  See xdr.h for more info on the interface to xdr.
 */

#include "compat.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libarpc/arpc.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>

/**
 * XDR an indirect pointer
 *
 * xdr_reference is for recursively translating a structure that is
 * referenced by a pointer inside the structure that is currently being
 * translated.  pp references a pointer to storage. If *pp is null
 * the  necessary storage is allocated.
 * size is the sizeof the referneced structure.
 * proc is the routine to handle the referenced structure.
 *
 * @param xdrs
 * @param pp - the pointer to work on
 * @param size - size of the object pointed to
 * @param proc - xdr routine to handle the object 
 * @return
 */
axdr_ret_t
axdr_reference(axdr_state_t *xdrs, caddr_t *pp, 
	       u_int size, axdrproc_t proc)
{
	caddr_t loc = *pp;
	axdr_ret_t rval;

	if (loc == NULL) {
		switch (xdrs->x_op) {
		case AXDR_FREE:
		case AXDR_STRINGIFY:
			return AXDR_DONE;

		case AXDR_DECODE_ASYNC:
		case AXDR_DECODE:
			*pp = loc = (caddr_t) mem_alloc(size);
			if (loc == NULL) {
				warnx("axdr_reference: out of memory");
				return AXDR_ERROR;
			}
			memset(loc, 0, size);
			break;

		case AXDR_ENCODE:
		case AXDR_ENCODE_ASYNC:
			break;
		default:
			return AXDR_ERROR;
		}
	}

	rval = (*proc)(xdrs, loc);

	if (xdrs->x_op == AXDR_FREE) {
		mem_free(loc, size);
		*pp = NULL;
	}
	return rval;
}


/*
 * axdr_pointer():
 *
 * XDR a pointer to a possibly recursive data structure. This
 * differs with axdr_reference in that it can serialize/deserialiaze
 * trees correctly.
 *
 *  What's sent is actually a union:
 *
 *  union object_pointer switch (boolean b) {
 *  case TRUE: object_data data;
 *  case FALSE: void nothing;
 *  }
 *
 * > objpp: Pointer to the pointer to the object.
 * > obj_size: size of the object.
 * > axdr_obj: routine to XDR an object.
 *
 */
axdr_ret_t
axdr_pointer(axdr_state_t *xdrs, char **objpp, 
	     u_int obj_size, axdrproc_t axdr_obj)
{
	axdr_ret_t rval;
	bool_t	cleanup;
	bool_t more_data;
	int	state = 0;

	if (xdrs->x_op == AXDR_STRINGIFY) {
		if (*objpp != NULL) {
			return axdr_reference(xdrs, objpp, obj_size, axdr_obj);
		} else {
			return AXDR_DONE;
		}
	}

	rval = axdr_async_setup(xdrs, &axdr_pointer, &cleanup, &state,
			       0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	more_data = (*objpp != NULL);

	switch (state) {
	case 0:
		rval = axdr_bool(xdrs, &more_data);
		if (rval != AXDR_DONE) {
			goto out;
		}
		if (!more_data) {
			*objpp = NULL;
			break; /* done */
		}
		state = 1;
		/* fallthrough */
	case 1:
		rval = axdr_reference(xdrs, objpp, obj_size, axdr_obj);
		if (rval != AXDR_DONE) {
			goto out;
		}
		break; /* done */
	default:
		rval = AXDR_ERROR;
	}

out:
	axdr_async_teardown(xdrs, &axdr_pointer, state, cleanup, rval);
	return rval;
}

/* 
 * Local Variables:
 * tab-width:8
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 * 
 */
