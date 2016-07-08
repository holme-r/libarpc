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
 * xdr_mem.h, XDR implementation using memory buffers.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * If you have some data to be interpreted as external data representation
 * or to be converted to external data representation in a memory buffer,
 * then this is the package for you.
 *
 */

#include "compat.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <libarpc/arpc.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>
#include "xdr_com.h"

static void xdrmem_destroy(axdr_state_t *);
static axdr_ret_t xdrmem_getint32_aligned(axdr_state_t *, int32_t *);
static axdr_ret_t xdrmem_putint32_aligned(axdr_state_t *, const int32_t *);
static axdr_ret_t xdrmem_getint32_unaligned(axdr_state_t *, int32_t *);
static axdr_ret_t xdrmem_putint32_unaligned(axdr_state_t *, const int32_t *);
static axdr_ret_t xdrmem_getbytes(axdr_state_t *, char *, size_t);
static axdr_ret_t xdrmem_putbytes(axdr_state_t *, const char *, size_t);
/* XXX: w/64-bit pointers, u_int not enough! */
static off_t xdrmem_getpos(axdr_state_t *);
static axdr_ret_t xdrmem_setpos(axdr_state_t *, off_t);
static int32_t *xdrmem_inline_aligned(axdr_state_t *, size_t);
static int32_t *xdrmem_inline_unaligned(axdr_state_t *, size_t);
static axdr_ret_t xdrmem_set_name(axdr_state_t *, const char *name, bool_t first, 
				 int *offp);
static axdr_ret_t xdrmem_add_value(axdr_state_t *, const char *str);
static axdr_ret_t xdrmem_add_bin(axdr_state_t *, const char *buf, int len);
static axdr_ret_t xdrmem_control(axdr_state_t *xdrs,
				 axdr_cmd_t cmd, void *arg);


static const axdr_ops_t xdrmem_ops_aligned = {
	xdrmem_getint32_aligned,
	xdrmem_putint32_aligned,
	xdrmem_getbytes,
	xdrmem_putbytes,
	xdrmem_getpos,
	xdrmem_setpos,
	xdrmem_inline_aligned,
	xdrmem_destroy,
	xdrmem_control, 
	xdrmem_set_name,
	xdrmem_add_value,
	xdrmem_add_bin
};

static const axdr_ops_t xdrmem_ops_unaligned = {
	xdrmem_getint32_unaligned,
	xdrmem_putint32_unaligned,
	xdrmem_getbytes,
	xdrmem_putbytes,
	xdrmem_getpos,
	xdrmem_setpos,
	xdrmem_inline_unaligned,
	xdrmem_destroy,
	xdrmem_control, 
	xdrmem_set_name,
	xdrmem_add_value,
	xdrmem_add_bin
};

/*
 * The procedure xdrmem_create initializes a stream descriptor for a
 * memory buffer.
 */
void
axdrmem_create(axdr_state_t *xdrs, char *addr, u_int size, axdr_op_t op)
{

	xdrs->x_op = op;
	xdrs->x_ops = ((unsigned long)addr & (sizeof(int32_t) - 1))
		? &xdrmem_ops_unaligned : &xdrmem_ops_aligned;
	xdrs->x_private = xdrs->x_base = addr;
	xdrs->x_handy = size;
	xdrs->x_async = NULL;
}

/*ARGSUSED*/
static void
xdrmem_destroy(axdr_state_t *xdrs)
{

}

static axdr_ret_t
xdrmem_getint32_aligned(axdr_state_t *xdrs, int32_t *lp)
{
	if (xdrs->x_handy < sizeof(int32_t)) {
		return AXDR_ERROR;
	}
	xdrs->x_handy -= sizeof(int32_t);
	*lp = ntoh32(*(int32_t *)xdrs->x_private);
	xdrs->x_private = (char *)(xdrs->x_private + sizeof(int32_t));
	return AXDR_DONE;
}

static axdr_ret_t
xdrmem_putint32_aligned(axdr_state_t *xdrs, const int32_t *lp)
{
	if (xdrs->x_handy < sizeof(int32_t)) {
		return AXDR_ERROR;
	}
	xdrs->x_handy -= sizeof(int32_t);
	*(int32_t *)xdrs->x_private = hton32(*lp);
	xdrs->x_private = (char *)xdrs->x_private + sizeof(int32_t);
	return AXDR_DONE;
}

static axdr_ret_t
xdrmem_getint32_unaligned(axdr_state_t *xdrs, int32_t *lp)
{
	u_int32_t l;

	if (xdrs->x_handy < sizeof(int32_t)) {
		return AXDR_ERROR;
	}
	xdrs->x_handy -= sizeof(int32_t);
	memmove(&l, xdrs->x_private, sizeof(int32_t));
	*lp = ntohl(l);
	xdrs->x_private = (char *)xdrs->x_private + sizeof(int32_t);
	return AXDR_DONE;
}

static axdr_ret_t
xdrmem_putint32_unaligned(axdr_state_t *xdrs, const int32_t *lp)
{
	u_int32_t l;

	if (xdrs->x_handy < sizeof(int32_t)) {
		return AXDR_ERROR;
	}
	xdrs->x_handy -= sizeof(int32_t);
	l = htonl((u_int32_t)*lp);
	memmove(xdrs->x_private, &l, sizeof(int32_t));
	xdrs->x_private = (char *)xdrs->x_private + sizeof(int32_t);
	return AXDR_DONE;
}

static axdr_ret_t
xdrmem_getbytes(axdr_state_t *xdrs, char *addr, size_t len)
{
	if (xdrs->x_handy < len) {
		return AXDR_ERROR;
	}
	xdrs->x_handy -= len;
	memmove(addr, xdrs->x_private, len);
	xdrs->x_private = (char *)xdrs->x_private + len;
	return AXDR_DONE;
}

static axdr_ret_t
xdrmem_putbytes(axdr_state_t *xdrs, const char *addr, size_t len)
{
	if (xdrs->x_handy < len) {
		return AXDR_ERROR;
	}
	xdrs->x_handy -= len;
	memmove(xdrs->x_private, addr, len);
	xdrs->x_private = (char *)xdrs->x_private + len;
	return AXDR_DONE;
}

static off_t
xdrmem_getpos(axdr_state_t *xdrs)
{
	/* XXX w/64-bit pointers, u_int not enough! */
	return (u_int)((u_long)xdrs->x_private - (u_long)xdrs->x_base);
}

static axdr_ret_t
xdrmem_setpos(axdr_state_t *xdrs, off_t pos)
{
	char *newaddr = xdrs->x_base + pos;
	char *lastaddr = (char *)xdrs->x_private + xdrs->x_handy;

	if (newaddr > lastaddr) {
		return AXDR_ERROR;
	}
	xdrs->x_private = newaddr;
	xdrs->x_handy = (u_int)(lastaddr - newaddr); /* XXX sizeof(u_int) <? sizeof(ptrdiff_t) */
	return AXDR_DONE;
}

static int32_t *
xdrmem_inline_aligned(axdr_state_t *xdrs, size_t len)
{
	int32_t *buf = 0;

	if (xdrs->x_handy >= len) {
		xdrs->x_handy -= len;
		buf = (int32_t *)xdrs->x_private;
		xdrs->x_private = (char *)xdrs->x_private + len;
	}
	return (buf);
}

/* ARGSUSED */
static int32_t *
xdrmem_inline_unaligned(axdr_state_t *xdrs, size_t len)
{
	return (0);
}

static axdr_ret_t
xdrmem_set_name(axdr_state_t *xdrs, const char *name, bool_t val, int *offp)
{
	return AXDR_ERROR;
}

static axdr_ret_t
xdrmem_add_value(axdr_state_t *xdrs, const char *str)
{
	return AXDR_ERROR;
}

static axdr_ret_t
xdrmem_add_bin(axdr_state_t *xdrs, const char *buf, int len)
{
	return AXDR_ERROR;
}

static axdr_ret_t
xdrmem_control(axdr_state_t *xdrs, axdr_cmd_t cmd, void *arg)
{
	if (xdrs->x_ops != &xdrmem_ops_aligned &&
	    xdrs->x_ops != &xdrmem_ops_unaligned) {
		return AXDR_ERROR;
	}

	switch (cmd) {
	case AR_XDRGET_EOR:
		if (xdrs->x_handy <= 0) {
			*((bool_t *)arg) = TRUE;
		} else {
			*((bool_t *)arg) = FALSE;
		}			
		return AXDR_DONE;
	case AR_XDRGET_AVAIL:
		/* return available bytes */
		*((off_t *)arg) = xdrs->x_handy;
		return AXDR_DONE;
	default:
		return axdr_control_default(xdrs, cmd, arg);
	}
}
