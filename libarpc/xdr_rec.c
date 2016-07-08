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
 * xdr_rec.c, Implements TCP/IP based XDR streams with a "record marking"
 * layer above tcp (for rpc's use).
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * These routines interface XDRSTREAMS to a tcp/ip connection.
 * There is a record marking layer between the xdr stream
 * and the tcp transport level.  A record is composed on one or more
 * record fragments.  A record fragment is a thirty-two bit header followed
 * by n bytes of data, where n is contained in the header.  The header
 * is represented as a htonl(u_long).  Thegh order bit encodes
 * whether or not the fragment is the last fragment of the record
 * (1 => fragment is last, 0 => more fragments to follow. 
 * The other 31 bits encode the byte length of the fragment.
 */

#include "compat.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <libarpc/arpc.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>
#include <stddef.h>
#include "xdr_com.h"

static axdr_ret_t	xdrrec_getint32(axdr_state_t *, int32_t *);
static axdr_ret_t	xdrrec_putint32(axdr_state_t *, const int32_t *);
static axdr_ret_t	xdrrec_getbytes(axdr_state_t *, char *, size_t);

static axdr_ret_t	xdrrec_putbytes(axdr_state_t *, const char *, size_t);
static off_t		xdrrec_getpos(axdr_state_t *);
static axdr_ret_t	xdrrec_setpos(axdr_state_t *, off_t);
static int32_t 		*xdrrec_inline(axdr_state_t *, size_t);
static void		xdrrec_destroy(axdr_state_t *);
static axdr_ret_t	xdrrec_set_name(axdr_state_t *, const char *name,
					bool_t, int *offp);
static axdr_ret_t	xdrrec_add_value(axdr_state_t *, const char *str);
static axdr_ret_t	xdrrec_add_bin(axdr_state_t *, const char *buf,
				       int len);
static axdr_ret_t	xdrrec_control(axdr_state_t *, axdr_cmd_t, void *);

static const axdr_ops_t xdrrec_ops = {
	xdrrec_getint32,
	xdrrec_putint32,
	xdrrec_getbytes,
	xdrrec_putbytes,
	xdrrec_getpos,
	xdrrec_setpos,
	xdrrec_inline,
	xdrrec_destroy,
	xdrrec_control,
	xdrrec_set_name,
	xdrrec_add_value,
	xdrrec_add_bin
};

/*
 * A record is composed of one or more record fragments.
 * A record fragment is a four-byte header followed by zero to
 * 2**32-1 bytes.  The header is treated as a long unsigned and is
 * encode/decoded to the network via htonl/ntohl.  The low order 31 bits
 * are a byte count of the fragment.  The highest order bit is a boolean:
 * 1 => this fragment is the last fragment of the record,
 * 0 => this fragment is followed by more fragment(s).
 *
 * The fragment/record machinery is not general;  it is constructed to
 * meet the needs of xdr and rpc based on tcp.
 */

#define LAST_FRAG ((u_int32_t)(1 << 31))

typedef struct rec_strm {
	char *tcp_handle;
	/*
	 * out-goung bits
	 */
	axdrrec_iofn_t writeit;
	char *out_base;	/* output buffer (points to frag header) */
	char *out_finger;	/* next output position */
	char *out_boundry;	/* data cannot up to this address */
	u_int32_t *frag_header;	/* beginning of curren fragment */
	bool_t frag_sent;	/* true if buffer sent in middle of record */
	/*
	 * in-coming bits
	 */
	axdrrec_iofn_t readit;
	u_long in_size;	/* fixed size of the input buffer */
	char *in_base;
	char *in_finger;	/* location of next byte to be had */
	char *in_boundry;	/* can read up to this location */
	long fbtbc;		/* fragment bytes to be consumed */
	bool_t last_frag;
	u_int sendsize;
	u_int recvsize;
} RECSTREAM;

static u_int		fix_buf_size(u_int);
static axdr_ret_t	flush_out(axdr_state_t *, RECSTREAM *, bool_t);
static axdr_ret_t	get_input_bytes(RECSTREAM *, int);
static axdr_ret_t	set_input_fragment(RECSTREAM *);


/**
 * Create an xdr handle for xdrrec
 * 
 * xdrrec_create fills in xdrs.  Sendsize and recvsize are
 * send and recv buffer sizes (0 => use default).
 * tcp_handle is an opaque handle that is passed as the first parameter to
 * the procedures readit and writeit.  Readit and writeit are read and
 * write respectively.   They have the prototype:
 *
 *  int func(void *opaque, void *buf, size_t *lenp)
 *
 * They work like the read/write system calls except that the length is 
 * and input/output parameter, intead of just an input.  The value pointed
 * to by lenp must be intiailized to the size of the buffer passed in.  On
 * return it contains the number of bytes read or written. The return
 * value is 0 on success, and on failure it is non-zero errno error code
 * value.  In addition, the calls take a tcp_handle instead of a file
 * descriptor.
 *
 * @param xdrs - xdr context
 * @param sendsize - send buffer size to create
 * @param recvsize - receive buffer size to create
 * @param handle - opaque handle for readit/writeit
 * @param readit - read io function
 * @param writeit - write io function
 * @return - 0 on success, non-zero errno error code value on failure
 */
int 
axdrrec_create(axdr_state_t *xdrs, u_int sendsize, u_int recvsize, 
	       void *tcp_handle, axdrrec_iofn_t readit, axdrrec_iofn_t writeit)
{
	RECSTREAM *rstrm;

	rstrm = mem_alloc(sizeof(RECSTREAM));
	if (rstrm == NULL) {
		warnx("xdrrec_create: out of memory");
		/* 
		 *  This is bad.  Should rework xdrrec_create to 
		 *  return a handle, and in this case return NULL
		 */
		return ENOMEM;
	}
	rstrm->sendsize = sendsize = fix_buf_size(sendsize);
	rstrm->out_base = mem_alloc(rstrm->sendsize);
	if (rstrm->out_base == NULL) {
		warnx("xdrrec_create: out of memory");
		mem_free(rstrm, sizeof(RECSTREAM));
		return ENOMEM;
	}
	rstrm->recvsize = recvsize = fix_buf_size(recvsize);
	rstrm->in_base = mem_alloc(recvsize);
	if (rstrm->in_base == NULL) {
		warnx("xdrrec_create: out of memory");
		mem_free(rstrm->out_base, sendsize);
		mem_free(rstrm, sizeof(RECSTREAM));
		return ENOMEM;
	}
	/*
	 * now the rest ...
	 */
	xdrs->x_ops = &xdrrec_ops;
	xdrs->x_private = rstrm;
	rstrm->tcp_handle = tcp_handle;
	rstrm->readit = readit;
	rstrm->writeit = writeit;
	rstrm->out_finger = rstrm->out_boundry = rstrm->out_base;
	rstrm->frag_header = (u_int32_t *)(void *)rstrm->out_base;
	rstrm->out_finger += sizeof(u_int32_t);
	rstrm->out_boundry += sendsize;
	rstrm->frag_sent = FALSE;
	rstrm->in_size = recvsize;
	rstrm->in_boundry = rstrm->in_base;
	rstrm->in_finger = (rstrm->in_boundry += recvsize);
	rstrm->fbtbc = 0;
	rstrm->last_frag = TRUE;

	return 0;
}


/*
 * The reoutines defined below are the xdr ops which will go into the
 * xdr handle filled in by xdrrec_create.
 */
static axdr_ret_t 
xdrrec_getint32(axdr_state_t *xdrs, int32_t *ip)
{
	axdr_ret_t 	rval;
	RECSTREAM	*rstrm;
	int32_t 	*buflp;
	int32_t 	i32;
	uint8_t		lbuf[4];
	int		lsize;
	int		current;

	rstrm = (RECSTREAM *)(xdrs->x_private);
	buflp = (int32_t *)(void *)(rstrm->in_finger);
	current = rstrm->in_boundry - rstrm->in_finger;

	/* fastpath: we have all the required data in the buffer in the
	 * current record. This should not be possible if we're in the
	 * middle of a paused operation since that would imply somebody
	 * besides us filled the buffer.
	 */
	if (current >= sizeof(int32_t) && rstrm->fbtbc >= sizeof(int32_t)) {
		i32 = *buflp;
		*ip = ntoh32(i32);
		rstrm->fbtbc -= sizeof(int32_t);
		rstrm->in_finger += sizeof(int32_t);
		return AXDR_DONE;
	}

	/* We have to do a lot of work to handle the case where our 'long'
	 * straddles a record boundary for correct pause operation. We
	 * don't generate records like this, but it's possible somebody else
	 * does so we have to support it.
	 */
	while (rstrm->fbtbc < sizeof(int32_t)) {
		rval = get_input_bytes(rstrm, sizeof(int32_t) - rstrm->fbtbc + 
				       sizeof(u_int32_t));
		if (rval != AXDR_DONE) {
			return rval;
		}

		lsize = rstrm->fbtbc;
		if (lsize > 0) {
			/* save off partial bytes */
			memcpy(lbuf, rstrm->in_finger, lsize);
			rstrm->in_finger += lsize;
			rstrm->fbtbc = 0;
		}
		/* this should not return waiting, since we gurantee
		 * data above.
		 */
		rval = set_input_fragment(rstrm);
		if (rval != AXDR_DONE) {
			return AXDR_ERROR;
		}
		if (lsize > 0) {
			/* restore partial bytes */
			if (rstrm->in_finger - lsize < rstrm->in_base) {
				memmove(rstrm->in_finger+sizeof(int32_t), 
					rstrm->in_finger,
					rstrm->in_boundry - rstrm->in_finger);
				rstrm->in_finger += sizeof(int32_t);
				rstrm->in_boundry += sizeof(int32_t);
			}
			rstrm->in_finger -= lsize;
			memcpy(rstrm->in_finger, lbuf, lsize);
			rstrm->fbtbc += lsize;
		}
	}

	current = rstrm->in_boundry - rstrm->in_finger;
	if (current < sizeof(int32_t)) {
		rval = get_input_bytes(rstrm, sizeof(int32_t));
		if (rval != AXDR_DONE) {
			return rval;
		}
	}

	buflp = (int32_t *)(void *)(rstrm->in_finger);
	i32 = *buflp;
	*ip = ntoh32(i32);
	rstrm->fbtbc -= sizeof(int32_t);
	rstrm->in_finger += sizeof(int32_t);
	return AXDR_DONE;
}

static axdr_ret_t 
xdrrec_putint32(axdr_state_t *xdrs, const int32_t *ip)
{
	axdr_ret_t	rval;
	RECSTREAM	*rstrm;
	int32_t		*dest_lp;
	int32_t		val;

	rstrm = (RECSTREAM *)xdrs->x_private;
	dest_lp = (int32_t *)rstrm->out_finger;
	
	if (((char *)&dest_lp[1]) > rstrm->out_boundry) {
		/*
		 * this case should almost never happen so the code is
		 * inefficient
		 */
		rval = flush_out(xdrs, rstrm, FALSE);
		if (rval != AXDR_DONE) {
			return rval;
		}
		dest_lp = (int32_t *)rstrm->out_finger;
	}
	val = *ip;
	*dest_lp = hton32(val);
	rstrm->out_finger = (char *)&dest_lp[1];

	return AXDR_DONE;
}

static axdr_ret_t  /* must manage buffers, fragments, and records */
xdrrec_getbytes(axdr_state_t *xdrs, char *addr, size_t len)
{
	RECSTREAM	*rstrm;
	axdr_ret_t	rval;
	int		_off = 0;
	int 		current;
	int 		buffered;
	int		left;
	bool_t		cleanup;

	rstrm = (RECSTREAM *)(xdrs->x_private);

	rval = axdr_async_setup(xdrs, &xdrrec_getbytes, &cleanup,
				   &_off, 0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}
	/* fastpath: we have all the required data in the buffer in the
	 * current record. This should not be possible if we're in the
	 * middle of a paused operation since that would imply somebody
	 * besides us filled the buffer.
	 */
	current = rstrm->in_boundry - rstrm->in_finger;
	if (current > rstrm->fbtbc) {
		current = rstrm->fbtbc;
	}
	if (current >= len && _off == 0) {
		memcpy(addr, rstrm->in_finger, len);
		rstrm->in_finger += len;
		rstrm->fbtbc -= len;
		axdr_async_teardown(xdrs, &xdrrec_getbytes, _off, 
				   cleanup, rval);
		return AXDR_DONE;
	}

	while (_off < len) {
		current = (int)rstrm->fbtbc;
		buffered = rstrm->in_boundry - rstrm->in_finger;
		if (current == 0 || buffered < 1) {
			if (current == 0) {
				if (rstrm->last_frag) {
					rval = AXDR_ERROR;
					goto out;
				}
				rval = set_input_fragment(rstrm);
			} else {
				rval = get_input_bytes(rstrm, 1);
			}
			if (rval != AXDR_DONE) {
				goto out;
			}
			continue;
		}
		current = (buffered < current) ? buffered : current;
		left = len - _off;
		current = (left < current) ? left : current;
		memcpy(&addr[_off], rstrm->in_finger, current);
		rstrm->in_finger += current;
		rstrm->fbtbc -= current;
		_off += current;
	}
	
	if (_off > len) {
		rval = AXDR_ERROR;
	}

out:
	axdr_async_teardown(xdrs, &xdrrec_getbytes, _off, cleanup, rval);
	return rval;
}

static axdr_ret_t 
xdrrec_putbytes(axdr_state_t *xdrs, const char *addr, size_t len)
{
	axdr_ret_t	rval;
	RECSTREAM	*rstrm;
	size_t 		current;
	size_t 		left;
	int		_off = 0;
	bool_t		cleanup;

	rstrm = (RECSTREAM *)(xdrs->x_private);

	/* 
	 * fastpath: we have all the required space in the buffer.  This
	 * should not be possible if we're in the middle of a paused
	 * operation since that would imply somebody besides us drained
	 * the buffer.
	 */
	current = rstrm->out_boundry - rstrm->out_finger;
	if (current >= len) {
		memmove(rstrm->out_finger, addr, len);
		rstrm->out_finger += len;
		return AXDR_DONE;
	}

	rval = axdr_async_setup(xdrs, &xdrrec_putbytes, &cleanup,
				   &_off, 0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	while (_off < len) {
		current = rstrm->out_boundry - rstrm->out_finger;
		if (current == 0) {
			rval = flush_out(xdrs, rstrm, FALSE);
			if (rval != AXDR_DONE) {
				goto out;
			}
			continue;
		}
		left = len - _off;
		current = (left < current) ? left : current;
		memmove(rstrm->out_finger, &addr[_off], current);
		rstrm->out_finger += current;
		_off += current;
	}

	if (_off > len) {
		return AXDR_ERROR;
	}

out:
	axdr_async_teardown(xdrs, &xdrrec_putbytes, _off, cleanup, rval);
	return rval;
}

static off_t
xdrrec_getpos(axdr_state_t *xdrs)
{
	RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;
	off_t pos;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		pos = rstrm->out_finger - rstrm->out_base;
		break;
	case AXDR_DECODE:
	case AXDR_DECODE_ASYNC:
		pos = rstrm->in_boundry - rstrm->in_finger;
		break;
	default:
		pos = (off_t) -1;
		break;
	}
	return pos;
}

static axdr_ret_t
xdrrec_setpos(axdr_state_t *xdrs, off_t pos)
{
	RECSTREAM *rstrm;
	off_t currpos;
	off_t delta;
	char *newpos;

	rstrm = (RECSTREAM *)xdrs->x_private;
	currpos = xdrrec_getpos(xdrs);
	delta = currpos - pos;

	if ((int)currpos == -1) {
		return AXDR_ERROR;
	}
		
	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		newpos = rstrm->out_finger - delta;
		if ((newpos > (char *)(void *)(rstrm->frag_header)) &&
			(newpos < rstrm->out_boundry)) {
			rstrm->out_finger = newpos;
			return AXDR_DONE;
		}
		break;

	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		newpos = rstrm->in_finger - delta;
		if ((delta < (int)(rstrm->fbtbc)) &&
			(newpos <= rstrm->in_boundry) &&
			(newpos >= rstrm->in_base)) {
			rstrm->in_finger = newpos;
			rstrm->fbtbc -= delta;
			return AXDR_DONE;
		}
		break;
	case AXDR_FREE:
	case AXDR_STRINGIFY:
		break;
	}
	return AXDR_ERROR;
}

static int32_t *
xdrrec_inline(axdr_state_t *xdrs, size_t len)
{
	RECSTREAM *rstrm;
	int32_t *buf = NULL;

	rstrm = (RECSTREAM *)xdrs->x_private;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		if ((rstrm->out_finger + len) <= rstrm->out_boundry) {
			buf = (int32_t *)(void *)rstrm->out_finger;
			rstrm->out_finger += len;
		}
		break;

	case AXDR_DECODE:
	case AXDR_DECODE_ASYNC:
		if ((len <= rstrm->fbtbc) &&
			((rstrm->in_finger + len) <= rstrm->in_boundry)) {
			buf = (int32_t *)(void *)rstrm->in_finger;
			rstrm->fbtbc -= len;
			rstrm->in_finger += len;
		}
		break;
	case AXDR_FREE:
	case AXDR_STRINGIFY:
		break;
	}
	return (buf);
}

static void
xdrrec_destroy(axdr_state_t *xdrs)
{
	RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;

	mem_free(rstrm->out_base, rstrm->sendsize);
	mem_free(rstrm->in_base, rstrm->recvsize);
	mem_free(rstrm, sizeof(RECSTREAM));
}

static axdr_ret_t
xdrrec_eatrecord(RECSTREAM *rstrm)
{
	axdr_ret_t	rval;
	int		current;
	
	while (rstrm->fbtbc > 0) {
		current = rstrm->in_boundry - rstrm->in_finger;
		if (current == 0) {
			rval = get_input_bytes(rstrm, 1);
			if (rval != AXDR_DONE) {
				return rval;
			}
			continue;
		}
		if (current > rstrm->fbtbc) {
			current = rstrm->fbtbc;
		}
		rstrm->fbtbc -= current;
		rstrm->in_finger += current;
	}

	return AXDR_DONE;
}
		

/*
 * Exported routines to manage xdr records
 */

/*
 * Before reading (deserializing from the stream, one should always call
 * this procedure to guarantee proper record alignment.
 */
axdr_ret_t
axdrrec_skiprecord(axdr_state_t *xdrs)
{
	axdr_ret_t	rval;
	RECSTREAM	*rstrm;

	rstrm = (RECSTREAM *)(xdrs->x_private);
	while (rstrm->fbtbc > 0 || (! rstrm->last_frag)) {
		rval = xdrrec_eatrecord(rstrm);
		if (rval != AXDR_DONE) {
			return rval;
		}
		if (!rstrm->last_frag) {
			rval = set_input_fragment(rstrm);
			if (rval != AXDR_DONE) {
				return rval;
			}
		}
	}
	rstrm->last_frag = FALSE;
	return AXDR_DONE;
}

/*
 * Look ahead function.
 * Returns TRUE iff there is no more input in the buffer
 * after consuming the rest of the current record.
 */
axdr_ret_t
axdrrec_eof(axdr_state_t *xdrs, bool_t *retp)
{
	axdr_ret_t	rval;
	RECSTREAM	*rstrm;

	if (xdrs->x_ops != &xdrrec_ops) {
		return AXDR_ERROR;
	}

	rstrm = (RECSTREAM *)(xdrs->x_private);

	while (rstrm->fbtbc > 0 || (! rstrm->last_frag)) {
		rval = xdrrec_eatrecord(rstrm);
		if (rval != AXDR_DONE) {
			return rval;
		}

		if (!rstrm->last_frag) {
			rval = set_input_fragment(rstrm);
			if (rval != AXDR_DONE) {
				return rval;
			}
		}
	}
	
	if (rstrm->in_finger == rstrm->in_boundry) {
		*retp = TRUE;
	} else {
		*retp = FALSE;
	}
	return AXDR_DONE;
}

axdr_ret_t
axdrrec_empty(axdr_state_t *xdrs, bool_t *retp)
{
	RECSTREAM	*rstrm;

	rstrm = (RECSTREAM *)(xdrs->x_private);

	if (rstrm->in_finger == rstrm->in_boundry) {
		*retp = TRUE;
	} else {
		*retp = FALSE;
	}
	return AXDR_DONE;
}

/*
 * The client must tell the package when an end-of-record has occurred.
 * The second paraemters tells whether the record should be flushed to the
 * (output) tcp stream.  (This let's the package support batched or
 * pipelined procedure calls.)  TRUE => immmediate flush to tcp connection.
 */
axdr_ret_t
axdrrec_endofrecord(axdr_state_t *xdrs, bool_t sendnow)
{
	axdr_ret_t	rval;
	RECSTREAM	*rstrm;
	u_long		len;  /* fragment length */

	rstrm = (RECSTREAM *)(xdrs->x_private);

	if (sendnow || rstrm->frag_sent ||
		(rstrm->out_finger + sizeof(u_int32_t) >= rstrm->out_boundry)) {
		rval = flush_out(xdrs, rstrm, TRUE);
		if (rval == AXDR_DONE) {
			rstrm->frag_sent = FALSE;
		}
		return rval;
	}
	len = (rstrm->out_finger - (char *)rstrm->frag_header - 
		   sizeof(u_int32_t));
	*(rstrm->frag_header) = htonl((u_int32_t)len | LAST_FRAG);
	rstrm->frag_header = (u_int32_t *)(void *)rstrm->out_finger;
	rstrm->out_finger += sizeof(u_int32_t);
	return AXDR_DONE;
}


/*
 * Internal useful routines
 */
static axdr_ret_t
flush_out(axdr_state_t *xdrs, RECSTREAM *rstrm, bool_t eor)
{
	axdr_ret_t	rval;
	u_int32_t	eormask;
	u_int32_t	len;
	size_t		bufsize;
	int		_off = 0;
	int		ret;
	bool_t		cleanup;

	rval = axdr_async_setup(xdrs, &flush_out, &cleanup, &_off,
				   0, (void **) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	if (_off == 0) {
		eormask = (eor == TRUE) ? LAST_FRAG : 0;
		len = (rstrm->out_finger - (char *)rstrm->frag_header - 
			   sizeof(u_int32_t));
		*(rstrm->frag_header) = htonl(len | eormask);
	}
	len = rstrm->out_finger - rstrm->out_base;
	rval = AXDR_DONE;
	while (_off < len) {
		bufsize = len - _off;
		ret = (*(rstrm->writeit))(rstrm->tcp_handle, 
					  &rstrm->out_base[_off], &bufsize);
		if (ret != 0) {
			if (ret == EAGAIN) {
				rval = AXDR_WAITING;
			} else {
				rval = AXDR_ERROR;
			}
			goto out;
		}
		_off += bufsize;
	}

	if (_off > len) {
		rval = AXDR_ERROR;
		goto out;
	}

	rstrm->frag_header = (u_int32_t *)rstrm->out_base;
	rstrm->out_finger = ((char *)rstrm->out_base + 
				 sizeof(u_int32_t));
	rstrm->frag_sent = TRUE;

out:
	axdr_async_teardown(xdrs, &flush_out, _off, cleanup, rval);
	return rval;
}

/* knows nothing about records!  Only about input buffers */
static axdr_ret_t
get_input_bytes(RECSTREAM *rstrm, int len)
{
	size_t bufsize;
	size_t current;
	u_int32_t i;
	int ret;
	char *limit;
	char *where;

	/* make sure it's possible to fit the requested size in our buffer.
	 * Since we maintain our alignment across acceses, we have to 
	 * incorporate that into our math as well.
	 */
	if ((len + BYTES_PER_XDR_UNIT - 1) > rstrm->in_size) {
		/* no way to buffer this much */
		return AXDR_ERROR;
	}

	while ((current = (size_t)((long)rstrm->in_boundry -
				   (long)rstrm->in_finger)) < len) {
		i = (u_int32_t)((u_long)rstrm->in_boundry % 
				BYTES_PER_XDR_UNIT);
		if (current == 0) {
			where = rstrm->in_base;
			where += i;
			bufsize = (size_t)(rstrm->in_size - i);
			rstrm->in_finger = where;
			rstrm->in_boundry = where;
		} else {
			where = rstrm->in_boundry;
			limit = rstrm->in_base + rstrm->in_size;
			bufsize = limit - where;
		} 
		if ((current + bufsize) < len) {
			/* need to scrunch it into the beginning of the
			 * buffer so we have enough room.
			 */
			where = rstrm->in_base;
			where += i;
			memmove(where, rstrm->in_finger, current);
			rstrm->in_finger = where;
			where += current;
			rstrm->in_boundry = where;
			bufsize = (size_t)(rstrm->in_size - i - current);
		}

		ret = (*(rstrm->readit))(rstrm->tcp_handle, where, &bufsize); 
		if (ret != 0) {
			if (ret == EAGAIN) {
				return AXDR_WAITING;
			} else {
				return AXDR_ERROR;
			}
		}
		if (bufsize == 0) {
			/* this indicates a closed connection, which if
			 * we're expecting data is an error 
			 */
			return AXDR_ERROR;
		}
		rstrm->in_boundry += bufsize;
	}

	return AXDR_DONE;
}

/* next two bytes of the input stream are treated as a header */
static axdr_ret_t 
set_input_fragment(RECSTREAM *rstrm)
{
	axdr_ret_t rval;
	u_int32_t header;

	rval = get_input_bytes(rstrm, sizeof(header));
	if (rval != AXDR_DONE) {
		return rval;
	}

	memcpy(&header, rstrm->in_finger, sizeof(header));
	rstrm->in_finger += sizeof(header);
	header = ntohl(header);
	rstrm->last_frag = ((header & LAST_FRAG) == 0) ? FALSE : TRUE;
	/*
	 * Sanity check. Try not to accept wildly incorrect
	 * record sizes. Unfortunately, the only record size
	 * we can positively identify as being 'wildly incorrect'
	 * is zero. Ridiculously large record sizes may look wrong,
	 * but we don't have any way to be certain that they aren't
	 * what the client actually intended to send us.
	 */
	if (header == 0) {
		return AXDR_ERROR;
	}
	rstrm->fbtbc = header & (~LAST_FRAG);
	return AXDR_DONE;
}

static u_int
fix_buf_size(s)
	u_int s;
{

	if (s < 100)
		s = 4000;
	return (RNDUP(s));
}

static axdr_ret_t
xdrrec_set_name(axdr_state_t *xdrs, const char *name, bool_t val, int *offp)
{
	return AXDR_ERROR;
}
	
static axdr_ret_t
xdrrec_add_value(axdr_state_t *xdrs, const char *str)
{
	return AXDR_ERROR;
}

static axdr_ret_t
xdrrec_add_bin(axdr_state_t *xdrs, const char *buf, int len)
{
	return AXDR_ERROR;
}

static axdr_ret_t
xdrrec_control(axdr_state_t *xdrs, axdr_cmd_t cmd, void *arg)
{
	RECSTREAM	*rstrm;

	if (xdrs->x_ops != &xdrrec_ops) {
		return AXDR_ERROR;
	}

	rstrm = (RECSTREAM *)(xdrs->x_private);

	switch (cmd) {
	case AR_XDRGET_EOR:
		if (rstrm->fbtbc > 0 || !rstrm->last_frag) {
			*((bool_t *)arg) = FALSE;
		} else {
			*((bool_t *)arg) = TRUE;
		}
		return AXDR_DONE;
	case AR_XDRGET_AVAIL:
		/* return available bytes */
		*((off_t *)arg) = rstrm->fbtbc;
		return AXDR_DONE;
	default:
		return axdr_control_default(xdrs, cmd, arg);
	}
}

