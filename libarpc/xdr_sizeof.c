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
 * xdr_sizeof.c
 *
 * Copyright 1990 Sun Microsystems, Inc.
 *
 * General purpose routine to see how much space something will use
 * when serialized using XDR.
 */

#include "compat.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include <libarpc/arpc.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>

/* ARGSUSED */
static axdr_ret_t
x_putint32(axdr_state_t *xdrs, const int32_t *longp)
{
	xdrs->x_handy += BYTES_PER_XDR_UNIT;
	return (AXDR_DONE);
}

/* ARGSUSED */
static axdr_ret_t
x_putbytes(axdr_state_t *xdrs, const char *bp, size_t len)
{
	xdrs->x_handy += len;
	return (AXDR_DONE);
}

static off_t
x_getpostn(axdr_state_t *xdrs)
{
	return (xdrs->x_handy);
}

/* ARGSUSED */
static axdr_ret_t
x_setpostn(axdr_state_t *xdrs, off_t pos)
{
	/* This is not allowed */
	return (AXDR_ERROR);
}

static int32_t *
x_inline(axdr_state_t *xdrs, size_t len)
{
	if (len == 0) {
		return (NULL);
	}
	if (xdrs->x_op != AXDR_ENCODE) {
		return (NULL);
	}
	if (len < (size_t)xdrs->x_base) {
		/* x_private was already allocated */
		xdrs->x_handy += len;
		return ((int32_t *) xdrs->x_private);
	} else {
		/* Free the earlier space and allocate new area */
		if (xdrs->x_private)
			free(xdrs->x_private);
		if ((xdrs->x_private = (caddr_t) malloc(len)) == NULL) {
			xdrs->x_base = 0;
			return (NULL);
		}
		xdrs->x_base = (caddr_t) len;
		xdrs->x_handy += len;
		return ((int32_t *) xdrs->x_private);
	}
}

static int
harmless(void)
{
	/* Always return FALSE/NULL, as the case may be */
	return (0);
}

static void
x_destroy(axdr_state_t *xdrs)
{
	xdrs->x_handy = 0;
	xdrs->x_base = 0;
	if (xdrs->x_private) {
		free(xdrs->x_private);
		xdrs->x_private = NULL;
	}
	return;
}

unsigned long
axdr_sizeof(axdrproc_t func, void *data)
{
	axdr_state_t x;
	axdr_ops_t ops;
	bool_t stat;
	/* to stop ANSI-C compiler from complaining */
	typedef  axdr_ret_t (* dummyfunc1)(axdr_state_t *, int32_t *);
	typedef  axdr_ret_t (* dummyfunc2)(axdr_state_t *, caddr_t, size_t);

	memset(&ops, 0, sizeof(ops));

	ops.x_putunit = x_putint32;
	ops.x_putbytes = x_putbytes;
	ops.x_inline = x_inline;
	ops.x_getpostn = x_getpostn;
	ops.x_setpostn = x_setpostn;
	ops.x_destroy = x_destroy;

	/* the other harmless ones */
	ops.x_getunit =  (dummyfunc1) harmless;
	ops.x_getbytes = (dummyfunc2) harmless;

	x.x_op = AXDR_ENCODE;
	x.x_ops = &ops;
	x.x_handy = 0;
	x.x_private = (caddr_t) NULL;
	x.x_base = (caddr_t) 0;

	stat = func(&x, data);
	if (x.x_private)
		free(x.x_private);
	return (stat == AXDR_DONE ? (unsigned) x.x_handy: 0);
}

/*
 * Local Variables:
 * tab-width:8
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 *
 */

