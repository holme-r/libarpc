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
 * pmap_prot.c
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

axdr_ret_t
axdr_ar_pmap(axdr_state_t *xdrs, ar_pmap *objp)
{
	int		off;
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state = 0;
	rval = axdr_async_setup(xdrs, &axdr_ar_pmap, &cleanup,
	                       &state, 0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}
	switch (state) {
	case 0:
		rval = axdr_element(xdrs, ".pm_prog", TRUE,
				    (axdrproc_t)&axdr_u_long, 
				    &objp->pm_prog, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 1;
		/* fallthrough */
	case 1:
		rval = axdr_element(xdrs, ".pm_vers", FALSE, 
				    (axdrproc_t)&axdr_u_long,
				    &objp->pm_vers, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 2;
		/* fallthrough */
	case 2:
		rval = axdr_element(xdrs, ".pm_prot", FALSE, 
				    (axdrproc_t)&axdr_u_long, 
				    &objp->pm_prot, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 3;
		/* fallthrough */
	case 3:
		rval = axdr_element(xdrs, ".pm_port", FALSE, 
				    (axdrproc_t)&axdr_u_long,
				    &objp->pm_port, &off);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 4;
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
	axdr_async_teardown(xdrs, &axdr_ar_pmap, state, cleanup, rval);
	return rval;
}
