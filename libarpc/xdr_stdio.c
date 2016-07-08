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
 * xdr_stdio.c, XDR implementation on standard i/o file.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * This set of routines implements a XDR on a stdio stream.
 * XDR_ENCODE serializes onto the stream, XDR_DECODE de-serializes
 * from the stream.
 */

#include "compat.h"

#include <stdio.h>

#include <arpa/inet.h>
#include <libarpc/arpc.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>
#include "xdr_com.h"

static void xdrstdio_destroy(axdr_state_t *);
static axdr_ret_t xdrstdio_getunit(axdr_state_t *, int32_t *);
static axdr_ret_t xdrstdio_putunit(axdr_state_t *, const int32_t *);
static axdr_ret_t xdrstdio_getbytes(axdr_state_t *, char *, size_t);
static axdr_ret_t xdrstdio_putbytes(axdr_state_t *, const char *, size_t);
static off_t xdrstdio_getpos(axdr_state_t *);
static axdr_ret_t xdrstdio_setpos(axdr_state_t *, off_t);
static int32_t *xdrstdio_inline(axdr_state_t *, size_t);
static axdr_ret_t xdrstdio_set_name(axdr_state_t *, const char *name, bool_t, int *offp);
static axdr_ret_t xdrstdio_add_value(axdr_state_t *, const char *str);
static axdr_ret_t xdrstdio_add_bin(axdr_state_t *, const char *buf, int len);
static axdr_ret_t xdrstdio_control(axdr_state_t *xdrs,
				   axdr_cmd_t cmd, void *arg);

/*
 * Ops vector for stdio type XDR
 */
static const axdr_ops_t xdrstdio_ops = {
	xdrstdio_getunit,	/* deseraialize a long int */
	xdrstdio_putunit,	/* seraialize a long int */
	xdrstdio_getbytes,	/* deserialize counted bytes */
	xdrstdio_putbytes,	/* serialize counted bytes */
	xdrstdio_getpos,	/* get offset in the stream */
	xdrstdio_setpos,	/* set offset in the stream */
	xdrstdio_inline,	/* prime stream for inline macros */
	xdrstdio_destroy,	/* destroy stream */
	xdrstdio_control, 
	xdrstdio_set_name,	/* add component name for next value */
	xdrstdio_add_value,	/* add next stringified value */
	xdrstdio_add_bin, 	/* add next binary value */ 
};

/*
 * Initialize a stdio xdr stream.
 * Sets the xdr stream handle xdrs for use on the stream file.
 * Operation flag is set to op.
 */
void
axdrstdio_create(axdr_state_t *xdrs, FILE *file, axdr_op_t op)
{
	xdrs->x_op = op;
	xdrs->x_ops = &xdrstdio_ops;
	xdrs->x_private = file;
	xdrs->x_handy = 0;
	xdrs->x_base = 0;
}

/*
 * Destroy a stdio xdr stream.
 * Cleans up the xdr stream handle xdrs previously set up by xdrstdio_create.
 */
static void
xdrstdio_destroy(axdr_state_t *xdrs)
{
	(void)fflush((FILE *)xdrs->x_private);
		/* XXX: should we close the file ?? */
}

static axdr_ret_t
xdrstdio_getunit(axdr_state_t *xdrs, int32_t *ip)
{
	u_int32_t temp;

	if (fread(&temp, sizeof(int32_t), 1, (FILE *)xdrs->x_private) != 1) {
		return AXDR_ERROR;
	}
	*ip = ntoh32(temp);
	return AXDR_DONE;
}

static axdr_ret_t
xdrstdio_putunit(axdr_state_t *xdrs, const int32_t *ip)
{
	int32_t mycopy = hton32(*ip);

	if (fwrite(&mycopy, sizeof(int32_t), 1, 
		   (FILE *)xdrs->x_private) != 1) {
		return AXDR_ERROR;
	}
	return AXDR_DONE;
}

static axdr_ret_t
xdrstdio_getbytes(axdr_state_t *xdrs, char *addr, size_t len)
{

	if ((len != 0) && (fread(addr, (size_t)len, 1, 
				 (FILE *)xdrs->x_private) != 1)) {
		return AXDR_ERROR;
	}
	return AXDR_DONE;
}

static axdr_ret_t
xdrstdio_putbytes(axdr_state_t *xdrs, const char *addr, size_t len)
{
	if ((len != 0) && (fwrite(addr, (size_t)len, 1,
				  (FILE *)xdrs->x_private) != 1)) {
		return AXDR_ERROR;
	}
	return AXDR_DONE;
}

static off_t
xdrstdio_getpos(axdr_state_t *xdrs)
{
	return (ftell((FILE *)xdrs->x_private));
}

static axdr_ret_t
xdrstdio_setpos(axdr_state_t *xdrs, off_t pos)
{ 
	return ((fseek((FILE *)xdrs->x_private, (long)pos, SEEK_SET) < 0) ?
		AXDR_ERROR : AXDR_DONE);
}

/* ARGSUSED */
static int32_t *
xdrstdio_inline(axdr_state_t *xdrs, size_t len)
{
	/*
	 * Must do some work to implement this: must insure
	 * enough data in the underlying stdio buffer,
	 * that the buffer is aligned so that we can indirect through a
	 * long *, and stuff this pointer in xdrs->x_buf.  Doing
	 * a fread or fwrite to a scratch buffer would defeat
	 * most of the gains to be had here and require storage
	 * management on this buffer, so we don't do this.
	 */
	return (NULL);
}

static axdr_ret_t
xdrstdio_set_name(axdr_state_t *xdrs, const char *name, bool_t val, int *offp)
{
	return AXDR_ERROR;
}

static axdr_ret_t
xdrstdio_add_value(axdr_state_t *xdrs, const char *str)
{
	return AXDR_ERROR;
}

static axdr_ret_t
xdrstdio_add_bin(axdr_state_t *xdrs, const char *buf, int len)
{
	return AXDR_ERROR;
}

static axdr_ret_t
xdrstdio_control(axdr_state_t *xdrs, axdr_cmd_t cmd, void *arg)
{
	/* for now, we don't bother telling 'how much is left.. */
	return axdr_control_default(xdrs, cmd, arg);
}
