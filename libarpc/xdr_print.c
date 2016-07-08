/*
 * Copyright (C) 2010  Pace Plc
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Pace Plc nor the names of its
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

#include "compat.h"

#include <sys/param.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libarpc/arpc.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>

static void xdrstr_destroy(axdr_state_t *);
static axdr_ret_t xdrstr_getunit(axdr_state_t *, int32_t *);
static axdr_ret_t xdrstr_putunit(axdr_state_t *, const int32_t *);
static axdr_ret_t xdrstr_getbytes(axdr_state_t *, char *, size_t);
static axdr_ret_t xdrstr_putbytes(axdr_state_t *, const char *, size_t);
static off_t xdrstr_getpos(axdr_state_t *);
static axdr_ret_t xdrstr_setpos(axdr_state_t *, off_t);
static int32_t *xdrstr_inline(axdr_state_t *, size_t);
static axdr_ret_t xdrstr_set_name(axdr_state_t *, const char *name,
				  bool_t first, int *offp);
static axdr_ret_t xdrstr_add_value(axdr_state_t *, const char *str);
static axdr_ret_t xdrstr_add_bin(axdr_state_t *, const char *buf, int len);

static const axdr_ops_t xdrstr_ops = {
	xdrstr_getunit,
	xdrstr_putunit,
	xdrstr_getbytes,
	xdrstr_putbytes,
	xdrstr_getpos,
	xdrstr_setpos,
	xdrstr_inline,
	xdrstr_destroy,
	NULL,
	xdrstr_set_name,
	xdrstr_add_value,
	xdrstr_add_bin
};

struct xdrstr_s {
	FILE		*fp;
	char		*namebuf;
	int		 namelen;
	const char	*prefix;
	char		*buf;
	int		 bufoff;
	int		 buflen;
};

extern int
axdr_fprint_create(axdr_state_t *xdrs, FILE *fp, const char *prefix)
{
	struct xdrstr_s *xs;

	memset(xdrs, 0, sizeof(*xdrs));
	xdrs->x_op = AXDR_STRINGIFY;
	xs = malloc(sizeof(*xs));
	if (!xs) {
		return ENOMEM;
	}
	memset(xs, 0, sizeof(*xs));
	xs->fp = fp;
	xs->prefix = prefix;
	xdrs->x_private = xs;
	xdrs->x_ops = &xdrstr_ops;

	return 0;
}

extern int
axdr_snprint_create(axdr_state_t *xdrs, char *buf, int len)
{
	struct xdrstr_s *xs;

	memset(xdrs, 0, sizeof(*xdrs));
	xdrs->x_op = AXDR_STRINGIFY;
	xs = malloc(sizeof(*xs));
	if (!xs) {
		return ENOMEM;
	}
	memset(xs, 0, sizeof(*xs));
	xs->buf = buf;
	xs->buflen = len;
	xdrs->x_private = xs;
	xdrs->x_ops = &xdrstr_ops;

	return 0;
}

static void
xdrstr_destroy(axdr_state_t *xdrs)
{
	struct xdrstr_s *xs;

	xs = (struct xdrstr_s *)xdrs->x_private;
	if (xs) {
		if (xs->namebuf) {
			free(xs->namebuf);
		}
		xs->namebuf = NULL;
		free(xs);
	}
}

static axdr_ret_t
xdrstr_getunit(axdr_state_t *xdrs, int32_t *ptr)
{
	return AXDR_ERROR;
}

static axdr_ret_t
xdrstr_putunit(axdr_state_t *xdrs, const int32_t *ptr)
{
	return AXDR_ERROR;
}

static axdr_ret_t
xdrstr_getbytes(axdr_state_t *xdrs, char *buf, size_t len)
{
	return AXDR_ERROR;
}

static axdr_ret_t
xdrstr_putbytes(axdr_state_t *xdrs, const char *buf, size_t len)
{
	return AXDR_ERROR;
}

static off_t
xdrstr_getpos(axdr_state_t *xdrs)
{
	return 0;
}

static axdr_ret_t
xdrstr_setpos(axdr_state_t *xdrs, off_t pos)
{
	return AXDR_ERROR;
}

static int32_t *
xdrstr_inline(axdr_state_t *xdrs, size_t len)
{
	return NULL;
}

static axdr_ret_t
xdrstr_set_name(axdr_state_t *xdrs, const char *name, bool_t first, int *offp)
{
	struct xdrstr_s *xs;
	char *nbuf;
	int nlen;
	int len;
	int off;

	xs = (struct xdrstr_s *)xdrs->x_private;
	if (!xs) {
		return AXDR_ERROR;
	}

	if (xs->namebuf) {
		off = strlen(xs->namebuf);
	} else {
		off = 0;
	}

	if (!first) {
		if (!xs->namebuf) {
			return AXDR_ERROR;
		}
		if (*offp >= 0 && *offp < off) {
			xs->namebuf[*offp] = '\0';
			off = *offp;
		}
	}

	if (!name) {
		/* nothing to add */
		return AXDR_DONE;
	}

	len = strlen(name);
	nlen = off + len + 1;
	if (nlen > xs->namelen) {
		nbuf = realloc(xs->namebuf, nlen);
		if (!nbuf) {
			return AXDR_ERROR;
		}
		xs->namebuf = nbuf;
		xs->namelen = nlen;
	}
	snprintf(&xs->namebuf[off], xs->namelen - off, "%s", name);
	*offp = off;
	return AXDR_DONE;
}

static axdr_ret_t
xdrstr_add_value(axdr_state_t *xdrs, const char *str)
{
	struct xdrstr_s *xs;
	int off;

	xs = (struct xdrstr_s *)xdrs->x_private;
	if (!xs) {
		return AXDR_ERROR;
	}

	if (xs->fp) {
		if (xs->namebuf) {
			fprintf(xs->fp, "%s%s = %s\n", 
				xs->prefix ? xs->prefix : "", 
				xs->namebuf, str);
		} else {
			fprintf(xs->fp, "%s%s\n", 
				xs->prefix ? xs->prefix : "", str);
		}
	} else {
		off = xs->bufoff;
		if (xs->namebuf) {
			snprintf(&xs->buf[off], xs->buflen - off,
				 "%s%s%s = %s",
				 xs->bufoff == 0 ? "" : ", ", 
				 xs->prefix ? xs->prefix : "", 
				 xs->namebuf, str);
			off += strlen(&xs->buf[off]);
		} else {
			snprintf(&xs->buf[off], xs->buflen - off,
				 "%s%s%s", 
				 xs->bufoff == 0 ? "" : ", ", 
				 xs->prefix ? xs->prefix : "", str);
			off += strlen(&xs->buf[xs->bufoff]);
		}
		xs->bufoff = off;
	}

	return AXDR_DONE;
}

static axdr_ret_t
xdrstr_add_bin(axdr_state_t *xdrs, const char *buf, int len)
{
	struct xdrstr_s *xs;
	uint8_t val;
	int idx;
	int off;

	xs = (struct xdrstr_s *)xdrs->x_private;
	if (!xs) {
		return AXDR_ERROR;
	}

	if (xs->fp) {
		if (xs->prefix) {
			fprintf(xs->fp, "%s", xs->prefix);
		}
		if (xs->namebuf) {
			fprintf(xs->fp, "%s = ", xs->namebuf);
		}
		fprintf(xs->fp, "%s", len <= 0 ? "(void)" : "0x");

		for (idx = 0; idx < len; idx++) {
			val = (uint8_t)buf[idx];
			fprintf(xs->fp, "%02x", (uint32_t)val);
		}

		fprintf(xs->fp, "\n");
	} else {
		off = xs->bufoff;

		if (xs->prefix) {
			snprintf(&xs->buf[off], xs->buflen - off,
				 "%s", xs->prefix);
			off += strlen(&xs->buf[off]);
		}
		if (xs->namebuf) {
			snprintf(&xs->buf[off], xs->buflen - off,
				 "%s = ", xs->namebuf);
			off += strlen(&xs->buf[off]);
		}
		snprintf(&xs->buf[off], xs->buflen - off, "%s", 
			 len <= 0 ? "(void)" : "0x");
		off += strlen(&xs->buf[off]);

		for (idx = 0; idx < len; idx++) {
			val = (uint8_t)buf[idx];
			snprintf(&xs->buf[off], xs->buflen - off, 
				 "%02x", (uint32_t)val);
			off += strlen(&xs->buf[off]);
		}
		xs->bufoff = off;
	}

	return AXDR_DONE;
}
