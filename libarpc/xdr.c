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
 * xdr.c, Generic XDR routines implementation.
 *
 * Copyright (C) 1986, Sun Microsystems, Inc.
 *
 * These are the "generic" xdr routines used to serialize and de-serialize
 * most common data items.  See xdr.h for more info on the interface to
 * xdr.
 */

#include "compat.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>

#include <libarpc/arpc.h>
#include <libarpc/stack.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>

#include "xdr_com.h"


typedef quad_t		longlong_t;	/* ANSI long long type */
typedef u_quad_t	u_longlong_t;	/* ANSI unsigned long long type */

/*
 * constants specific to the xdr "protocol"
 */
#define XDR_FALSE	((int32_t) 0)
#define XDR_TRUE	((int32_t) 1)
#define LASTUNSIGNED	((u_int) 0-1)

/*
 * for unit alignment
 */
static const char axdr_zero[BYTES_PER_XDR_UNIT] = { 0, 0, 0, 0 };

/**
 * Setup potentially-asynchronous call.
 * @param statep	Pointer to our state variable, which should contain 
 * 			the starting state.
 *				  
 * @param statepp	Pointer to statep, which is what the caller should
 * 			be using afterward. In the synchronous case,
 * 			it points to state; in the async case, it
 * 			points to a stack that persists * between calls.
 */
axdr_ret_t
axdr_async_setup(axdr_state_t *xdrs, void *id, bool_t *cleanupp, int *statep, 
		 size_t extrasize, void **extra)
{
	int err;

	if (xdrs->x_op == AXDR_ENCODE_ASYNC || 
		xdrs->x_op == AXDR_DECODE_ASYNC) {
		if (!xdrs->x_async) {
			return AXDR_ERROR;
		}
		err = astk_enter(xdrs->x_async, id, statep, *statep,
				 extra, extrasize);
		if (err != 0) {
			return AXDR_ERROR;
		}
		*cleanupp = TRUE;
	} else {
		*cleanupp = FALSE;
	}
	return AXDR_DONE;
}

void
axdr_async_teardown(axdr_state_t *xdrs, void *id, int state,
			bool_t cleanup, int rval)
{
	if (cleanup) {
		astk_leave(xdrs->x_async, id, state, rval == AXDR_WAITING);
	}
}

/*
 * Free a data structure using XDR
 * Not a filter, but a convenient utility nonetheless
 */
void
axdr_free(axdrproc_t proc, void *objp)
{
	axdr_state_t x;
	memset(&x, 0, sizeof(x));
	x.x_op = AXDR_FREE;
	(*proc)(&x, objp);
}

/*
 * XDR nothing
 */
axdr_ret_t
axdr_void(void)
{
	return AXDR_DONE;
}


/*
 * XDR integers
 */
axdr_ret_t
axdr_int(axdr_state_t *xdrs, int *ip)
{
	axdr_ret_t rval;
	int32_t i32;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		i32 = (int32_t)*ip;
		return (axdr_putunit(xdrs, &i32));
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		rval = axdr_getunit(xdrs, &i32);
		if (rval == AXDR_DONE) {
			*ip = (int)i32;
		}
		return rval;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[12];
		snprintf(buf, sizeof(buf), "%d", *ip);
		return axdr_str_add_value(xdrs, buf);
	}
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}

/*
 * XDR unsigned integers
 */
axdr_ret_t
axdr_u_int(axdr_state_t *xdrs, u_int *up)
{
	axdr_ret_t rval;
	uint32_t u32;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		u32 = (uint32_t)*up;
		return (axdr_putunit(xdrs, (int32_t *)&u32));
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		rval = axdr_getunit(xdrs, (int32_t *)&u32);
		if (rval == AXDR_DONE) {
			*up = (u_int)u32;
		}
		return rval;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[12];
		snprintf(buf, sizeof(buf), "%u", *up);
		return axdr_str_add_value(xdrs, buf);
	}
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}


/*
 * XDR long integers
 * same as xdr_u_long - open coded to save a proc call!
 */
axdr_ret_t
axdr_long(axdr_state_t *xdrs, long *lp)
{
	axdr_ret_t rval;
	int32_t i32;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		i32 = (int32_t)*lp;
		return (axdr_putunit(xdrs, &i32));
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		rval = axdr_getunit(xdrs, &i32);
		if (rval == AXDR_DONE) {
			*lp = (long)i32;
		}
		return rval;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[12];
		snprintf(buf, sizeof(buf), "%ld", *lp);
		return axdr_str_add_value(xdrs, buf);
	}
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}

/*
 * XDR unsigned long integers
 * same as xdr_long - open coded to save a proc call!
 */
axdr_ret_t
axdr_u_long(axdr_state_t *xdrs, u_long *ulp)
{
	axdr_ret_t rval;
	uint32_t u32;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		u32 = (uint32_t)*ulp;
		return (axdr_putunit(xdrs, (int32_t *)&u32));
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		rval = axdr_getunit(xdrs, (int32_t *)&u32);
		if (rval == AXDR_DONE) {
			*ulp = (u_long)u32;
		}
		return rval;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[12];
		snprintf(buf, sizeof(buf), "%lu", *ulp);
		return axdr_str_add_value(xdrs, buf);
	}
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}


/*
 * XDR 32-bit integers
 * same as xdr_u_int32_t - open coded to save a proc call!
 */
axdr_ret_t
axdr_int32_t(axdr_state_t *xdrs, int32_t *int32_p)
{
	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		return (axdr_putunit(xdrs, int32_p));
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		return (axdr_getunit(xdrs, int32_p));
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[12];
		snprintf(buf, sizeof(buf), RPC_INT32_FMT, *int32_p);
		return axdr_str_add_value(xdrs, buf);
	}
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}

/*
 * XDR unsigned 32-bit integers
 * same as xdr_int32_t - open coded to save a proc call!
 */
axdr_ret_t
axdr_u_int32_t(axdr_state_t *xdrs, u_int32_t *u_int32_p)
{
	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		return (axdr_putunit(xdrs, (int32_t *)u_int32_p));
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		return (axdr_getunit(xdrs, (int32_t *)u_int32_p));
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[12];
		snprintf(buf, sizeof(buf), RPC_UINT32_FMT, *u_int32_p);
		return axdr_str_add_value(xdrs, buf);
	}
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}

/*
 * XDR POSIX uint32_t
 */
axdr_ret_t
axdr_uint32_t(axdr_state_t *xdrs, uint32_t *uint32_p)
{
	return axdr_u_int32_t(xdrs, uint32_p);
}

/*
 * XDR short integers
 */
axdr_ret_t
axdr_short(axdr_state_t *xdrs, short *sp)
{
	axdr_ret_t rval;
	int32_t i32;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		i32 = (int32_t)*sp;
		return (axdr_putunit(xdrs, &i32));
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		rval = axdr_getunit(xdrs, &i32);
		if (rval == AXDR_DONE) {
			*sp = (short)i32;
		}
		return rval;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[12];
		snprintf(buf, sizeof(buf), "%hd", *sp);
		return axdr_str_add_value(xdrs, buf);
	}
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}

/*
 * XDR unsigned short integers
 */
axdr_ret_t
axdr_u_short(axdr_state_t *xdrs, u_short *usp)
{
	axdr_ret_t rval;
	uint32_t u32;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		u32 = (uint32_t)*usp;
		return (axdr_putunit(xdrs, (int32_t *)&u32));
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		rval = axdr_getunit(xdrs, (int32_t *)&u32);
		if (rval == AXDR_DONE) {
			*usp = (u_short)u32;
		}
		return rval;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[12];
		snprintf(buf, sizeof(buf), "%hu", *usp);
		return axdr_str_add_value(xdrs, buf);
	}
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}


/*
 * XDR 16-bit integers
 */
axdr_ret_t
axdr_int16_t(axdr_state_t *xdrs, int16_t *int16_p)
{
	axdr_ret_t rval;
	int32_t i32;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		i32 = (int32_t)*int16_p;
		return (axdr_putunit(xdrs, &i32));
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		rval = axdr_getunit(xdrs, &i32);
		if (rval == AXDR_DONE) {
			*int16_p = (int16_t)i32;
		}
		return rval;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[12];
		snprintf(buf, sizeof(buf), RPC_INT16_FMT, *int16_p);
		return axdr_str_add_value(xdrs, buf);
	}
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}

/*
 * XDR unsigned 16-bit integers
 */
axdr_ret_t
axdr_u_int16_t(axdr_state_t *xdrs, u_int16_t *u_int16_p)
{
	axdr_ret_t rval;
	uint32_t u32;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		u32 = (uint32_t)*u_int16_p;
		return (axdr_putunit(xdrs, (int32_t *)&u32));
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		rval = axdr_getunit(xdrs, (int32_t *)&u32);
		if (rval == AXDR_DONE) {
			*u_int16_p = (u_int16_t)u32;
		}
		return rval;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[12];
		snprintf(buf, sizeof(buf), RPC_UINT16_FMT, *u_int16_p);
		return axdr_str_add_value(xdrs, buf);
	}
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}

/*
 *XDR POSIX uint16
 */
axdr_ret_t
axdr_uint16_t(axdr_state_t *xdrs, uint16_t *uint16_p)
{
	return axdr_u_int16_t(xdrs, uint16_p);
}


/*
 * XDR a char
 */
axdr_ret_t
axdr_char(axdr_state_t *xdrs, char *cp)
{
	axdr_ret_t rval;
	int i;

	i = (*cp);
	rval = axdr_int(xdrs, &i);
	if (rval == AXDR_DONE) {
		*cp = (char)i;
	}
	return rval;
}

/*
 * XDR an unsigned char
 */
axdr_ret_t
axdr_u_char(axdr_state_t *xdrs, u_char *cp)
{
	axdr_ret_t rval;
	u_int u;

	u = (*cp);
	rval = axdr_u_int(xdrs, &u);
	if (rval == AXDR_DONE) {
		*cp = (u_char)u;
	}
	return rval;
}

/*
 * XDR booleans
 */
axdr_ret_t
axdr_bool(axdr_state_t *xdrs, bool_t *bp)
{
	axdr_ret_t rval;
	int32_t i32;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		i32 = *bp ? XDR_TRUE : XDR_FALSE;
		return (axdr_putunit(xdrs, &i32));
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		rval = axdr_getunit(xdrs, &i32);
		if (rval == AXDR_DONE) {
			*bp = (i32 == XDR_FALSE) ? FALSE : TRUE;
		}
		return rval;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY:
		return axdr_str_add_value(xdrs, *bp ? "TRUE" : "FALSE");
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}

/*
 * XDR enumerations
 */
axdr_ret_t
axdr_enum(axdr_state_t *xdrs, enum_t *ep)
{
	enum sizecheck { SIZEVAL };	/* used to find the size of an enum */

	/*
	 * enums are treated as ints
	 */
	if (xdrs->x_op == AXDR_STRINGIFY) {
		char buf[32];
		snprintf(buf, sizeof(buf), "enum #" RPC_ENUM_FMT, *ep);
		return axdr_str_add_value(xdrs, buf);
	} else /* LINTED */ if (sizeof (enum sizecheck) == sizeof (long)) {
		return (axdr_long(xdrs, (long *)(void *)ep));
	} else /* LINTED */ if (sizeof (enum sizecheck) == sizeof (int)) {
		return (axdr_int(xdrs, (int *)(void *)ep));
	} else /* LINTED */ if (sizeof (enum sizecheck) == sizeof (short)) {
		return (axdr_short(xdrs, (short *)(void *)ep));
	} else {
		return AXDR_ERROR;
	}
}

/*
 * XDR opaque data
 * Allows the specification of a fixed size sequence of opaque bytes.
 * cp points to the opaque object and cnt gives the byte length.
 */
axdr_ret_t
axdr_opaque(axdr_state_t *xdrs, caddr_t cp, u_int cnt)
{
	axdr_ret_t rval;
	bool_t	cleanup;
	int	state;
	u_int	rndup;
	int	crud[BYTES_PER_XDR_UNIT];

	if (xdrs->x_op == AXDR_STRINGIFY) {
		return (*xdrs->x_ops->x_str_add_bin)(xdrs, cp, cnt);
	}

	/*
	 * if no data we are done
	 */
	if (cnt == 0 || xdrs->x_op == AXDR_FREE) {
		return AXDR_DONE;
	}
	/*
	 * round byte count to full xdr units
	 */
	rndup = cnt % BYTES_PER_XDR_UNIT;
	if (rndup > 0) {
		rndup = BYTES_PER_XDR_UNIT - rndup;
	}

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		state = 0;
		break;
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		state = 2;
		break;
	default:
		return AXDR_ERROR;
	}

	rval = axdr_async_setup(xdrs, &axdr_opaque, &cleanup, &state,
				0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	switch (state) {
	case 0:
		rval = axdr_putbytes(xdrs, cp, cnt);
		if (rval != AXDR_DONE) {
			break;
		}
		if (rndup == 0) {
			state = 4;	/* done */
			break;
		}
		state = 1;
		/* fallthrough */
	case 1:
		rval = axdr_putbytes(xdrs, axdr_zero, rndup);
		if (rval != AXDR_DONE) {
			break;
		}
		state = 4;
		break; /* done */
	case 2:
		rval = axdr_getbytes(xdrs, cp, cnt);
		if (rval != AXDR_DONE) {
			break;
		}
		if (rndup == 0) {
			state = 4;	/* done */
			break;
		}
		state = 3;
		/* fallthrough */
	case 3:
		rval = axdr_getbytes(xdrs, (caddr_t)(void *)crud, rndup);
		if (rval != AXDR_DONE) {
			break;
		}
		state = 4;
		break; /* done */
	default:
		rval = AXDR_ERROR;
	}

	axdr_async_teardown(xdrs, &axdr_opaque, state, cleanup, rval);
	return rval;
}

/*
 * XDR counted bytes
 * *cpp is a pointer to the bytes, *sizep is the count.
 * If *cpp is NULL maxsize bytes are allocated
 */
axdr_ret_t
axdr_bytes(axdr_state_t *xdrs, char **cpp, u_int *sizep, u_int maxsize)
{
	bool_t	cleanup;
	axdr_ret_t rval;
	u_int	nodesize;
	int	state = 0;
	char 	*sp = *cpp;  /* sp is the actual string pointer */

	if (xdrs->x_op == AXDR_FREE) {
		if (sp != NULL) {
			mem_free(sp, *sizep);
			*cpp = NULL;
		}
		return AXDR_DONE;
	}
	if (xdrs->x_op == AXDR_STRINGIFY) {
		return axdr_opaque(xdrs, sp, *sizep);
	}

	rval = axdr_async_setup(xdrs, &axdr_bytes, &cleanup, &state,
				0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	switch (state) {
	case 0:
		/*
		 * first deal with the length since xdr bytes are counted
		 */
		rval = axdr_u_int(xdrs, sizep); 
		if (rval == AXDR_WAITING) {
			break;
		}
		if (rval != AXDR_DONE) {
			goto out;
		}
		nodesize = *sizep;
		if (nodesize > maxsize) {
			rval = AXDR_ERROR;
			goto out;
		}
		if (xdrs->x_op == AXDR_DECODE_ASYNC ||
			xdrs->x_op == AXDR_DECODE) {
			if (nodesize == 0) {
				state = 2;
				break; /* done */
			}
			if (sp == NULL) {
				*cpp = sp = mem_alloc(nodesize);
			}
			if (sp == NULL) {
				warnx("xdr_bytes: out of memory");
				rval = AXDR_ERROR;
				goto out;
			}
		}
		state = 1;
		/* FALLTHROUGH */
	case 1:
		rval = (axdr_opaque(xdrs, sp, *sizep));
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 2;
		break;
	default:
		rval = AXDR_ERROR;
	}

out:
	axdr_async_teardown(xdrs, &axdr_bytes, state, cleanup, rval);
	return rval;
}

typedef struct xdr_encap_hack_s {
	axdrproc_t insideproc;
	va_list ap;
} xdr_encap_hack_t;

typedef axdr_ret_t (*axdrproc3_t)(axdr_state_t *, char **, u_int);
typedef axdr_ret_t (*axdrproc4_t)(axdr_state_t *, char **, u_int, axdrproc_t);

/** Hack to handle primitives with different argument lists. */
static axdr_ret_t
axdr_encap_hack(axdr_state_t *xdrs, xdr_encap_hack_t *hack)
{
	axdrproc_t p;

	p = hack->insideproc;

	if (p == (axdrproc_t)axdr_array) {
		char		**arg2 = va_arg(hack->ap, char**);
		u_int		*arg3 = va_arg(hack->ap, u_int*);
		u_int		arg4 = va_arg(hack->ap, u_int);
		u_int		arg5 = va_arg(hack->ap, u_int);
		axdrproc_t	arg6 = va_arg(hack->ap, axdrproc_t);
		return axdr_array(xdrs, arg2, arg3, arg4, arg5, arg6);
	} else if (p == (axdrproc_t)&axdr_bytes) {
		char	**arg2 = va_arg(hack->ap, char**);
		u_int	*arg3 = va_arg(hack->ap, u_int*);
		u_int	arg4 = va_arg(hack->ap, u_int);
		return axdr_bytes(xdrs, arg2, arg3, arg4);
	} else if (p == ((axdrproc_t)&axdr_opaque) ||
		   p == ((axdrproc_t)&axdr_string)) {
		char **arg2 = va_arg(hack->ap, char**);
		u_int  arg3 = va_arg(hack->ap, u_int);
		return (*((axdrproc3_t)p))(xdrs, arg2, arg3);
	} else if (p == ((axdrproc_t)&axdr_union)) {
		enum_t   *arg2 = va_arg(hack->ap, enum_t*);
		char	 *arg3 = va_arg(hack->ap, char*);
		const axdr_discrim_t *arg4;
		axdrproc_t arg5;
		arg4 = va_arg(hack->ap, const axdr_discrim_t *);
		arg5 = va_arg(hack->ap, axdrproc_t);
		return axdr_union(xdrs, arg2, arg3, arg4, arg5);
	} else if (p == ((axdrproc_t)&axdr_vector)) {
		char	 *arg2 = va_arg(hack->ap, char*);
		u_int	 arg3 = va_arg(hack->ap, u_int);
		u_int	 arg4 = va_arg(hack->ap, u_int);
		axdrproc_t arg5 = va_arg(hack->ap, axdrproc_t);
		return axdr_vector(xdrs, arg2, arg3, arg4, arg5);
	} else if (p == ((axdrproc_t)&axdr_reference) ||
		   p == ((axdrproc_t)&axdr_pointer)) {
		char	**arg2 = va_arg(hack->ap, char**);
		u_int	 arg3 = va_arg(hack->ap, u_int);
		axdrproc_t arg4 = va_arg(hack->ap, axdrproc_t);
		return (*((axdrproc4_t)p))(xdrs, arg2, arg3, arg4);
	} else {
		/* everything else takes a single pointer */
		void *arg2 = va_arg(hack->ap, void*);
		return (*p)(xdrs, arg2);
	}
}

axdr_ret_t
axdr_encap(axdr_state_t *xdrs, axdrproc_t insideproc, ...)
{
	axdr_ret_t rval;
	u_int size;
	int state = 0;
	int expected_size = 0;
	bool_t cleanup;
	xdr_encap_hack_t hack;
	int *sizep = &expected_size;
	int xtra = 0;

	hack.insideproc = insideproc;
	if (xdrs->x_op == AXDR_FREE || xdrs->x_op == AXDR_STRINGIFY) {
		state = 1; /* skip the size thing */
	} else if (xdrs->x_op == AXDR_DECODE ||
		   xdrs->x_op == AXDR_DECODE_ASYNC) {
		xtra = sizeof(int);
	}
	rval = axdr_async_setup(xdrs, &axdr_encap, &cleanup, &state,
				   xtra, (void**)&sizep);
	if (rval != AXDR_DONE) {
		return rval;
	}
	switch (state) {
	case 0:
		if (xdrs->x_op == AXDR_ENCODE ||
		    xdrs->x_op == AXDR_ENCODE_ASYNC) {
			va_start(hack.ap, insideproc);
			size = axdr_sizeof((axdrproc_t)axdr_encap_hack, &hack);
			va_end(hack.ap);
			assert(size % BYTES_PER_XDR_UNIT == 0);
		}

		rval = axdr_u_int(xdrs, &size);
		if (rval != AXDR_DONE) {
			goto out;
		}

		if (xdrs->x_op == AXDR_DECODE ||
		    xdrs->x_op == AXDR_DECODE_ASYNC) {
			/* save for validation */
			*sizep = size;
		}

		state = 1;
		/* FALLTHROUGH */
	case 1:
		va_start(hack.ap, insideproc);
		rval = axdr_encap_hack(xdrs, &hack);
		va_end(hack.ap);

		if (rval != AXDR_DONE) {
			goto out;
		}

		if (xdrs->x_op == AXDR_DECODE ||
		    xdrs->x_op == AXDR_DECODE_ASYNC) {
			/* validate size */
			va_start(hack.ap, insideproc);
			size = axdr_sizeof((axdrproc_t)axdr_encap_hack, &hack);
			va_end(hack.ap);
			if (size != *sizep) {
				rval = AXDR_ERROR;
				goto out;
			}
		}
		state = 2;
		break;
	default:
		rval = AXDR_ERROR;
	}

out:
	axdr_async_teardown(xdrs, &axdr_encap, state, cleanup, rval);
	return rval;
}

/*
 * Implemented here due to commonality of the object.
 */
axdr_ret_t
axdr_netobj(axdr_state_t *xdrs, netobj_t *np)
{
	return (axdr_bytes(xdrs, &np->n_bytes, &np->n_len, MAX_NETOBJ_SZ));
}

/**
 * XDR a descriminated union
 * Support routine for discriminated unions.
 * You create an array of xdrdiscrim structures, terminated with
 * an entry with a null procedure pointer.  The routine gets
 * the discriminant value and then searches the array of xdrdiscrims
 * looking for that value.  It calls the procedure given in the xdrdiscrim
 * to handle the discriminant.  If there is no specific routine a default
 * routine may be called.
 * If there is no specific or default routine an error is returned.
 * @param xdrs
 * @param dscmp - enum to decide which arm to work on 
 * @param unp - the union itself
 * @param choices - [value, xdr proc] for each arm
 * @param dfault - default xdr routine 
 * @return
 */
axdr_ret_t
axdr_union(axdr_state_t *xdrs, enum_t *dscmp, char *unp,
	   const axdr_discrim_t *choices, axdrproc_t dfault)
{
	axdr_ret_t rval;
	enum_t	dscm;
	int	state = 0;
	bool_t	cleanup;

	dscm = *dscmp;

	if (xdrs->x_op == AXDR_STRINGIFY) {
		char buf[32];
		int off;

		for (; choices->proc != NULL_axdrproc_t; choices++) {
			if (choices->value == dscm) {
				break;
			}
		}

		if (choices) {
			snprintf(buf, sizeof(buf), ".%s", choices->name);
		} else {
			snprintf(buf, sizeof(buf), ".<" RPC_INT32_FMT 
				 ">", dscm);
		}

		rval = axdr_str_set_name(xdrs, buf, TRUE, &off);
		if (rval != AXDR_DONE) {
			return rval;
		}

		if (choices) {
			rval = (*(choices->proc))(xdrs, unp);
		} else if (dfault != NULL_axdrproc_t) {
			rval = (*dfault)(xdrs, unp);
		} else {
			rval = AXDR_ERROR;
		}
		if (rval != AXDR_DONE) {
			return rval;
		}
		return axdr_str_set_name(xdrs, NULL, FALSE, &off);
	}

	rval = axdr_async_setup(xdrs, &axdr_union, &cleanup, &state,
				0, (void**) NULL);
	if (rval != AXDR_DONE) {
		return rval;
	}

	switch (state) {
	case 0:
		/*
		 * we deal with the discriminator;  it's an enum
		 */
		rval = axdr_enum(xdrs, dscmp);
		if (rval != AXDR_DONE) {
			goto out;
		}
		dscm = *dscmp;
		state = 1;
		/* fallthrough */
	case 1:
		/*
		 * search choices for a value that matches the discriminator.
		 * if we find one, execute the xdr routine for that value.
		 */
		for (; choices->proc != NULL_axdrproc_t; choices++) {
			if (choices->value == dscm) {
				break;
			}
		}

		if (choices) {
			rval = (*(choices->proc))(xdrs, unp);
		} else if (dfault != NULL_axdrproc_t) {
			rval = (*dfault)(xdrs, unp);
		} else {
			rval = AXDR_ERROR;
		}
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 2;
		break;  /* done */
	default:
		rval = AXDR_ERROR;
	}

out:
	axdr_async_teardown(xdrs, &axdr_union, state, cleanup, rval);
	return rval;
}


/*
 * Non-portable xdr primitives.
 * Care should be taken when moving these routines to new architectures.
 */


/*
 * XDR null terminated ASCII strings
 * xdr_string deals with "C strings" - arrays of bytes that are
 * terminated by a NULL character.  The parameter cpp references a
 * pointer to storage; If the pointer is null, then the necessary
 * storage is allocated.  The last parameter is the max allowed length
 * of the string as specified by a protocol.
 */
axdr_ret_t
axdr_string(axdr_state_t *xdrs, char **cpp, u_int maxsize)
{
	char		*sp = *cpp;	/*sp is the actual string pointer*/
	u_int		size = 0;
	u_int		nodesize;
	bool_t		cleanup;
	u_int		*sizep = &size;
	axdr_ret_t	rval;
	int		state = 0;

	/*
	 * first deal with the length since xdr strings are counted-strings
	 */
	switch (xdrs->x_op) {
	case AXDR_FREE:
		if (sp == NULL) {
			return AXDR_DONE;	/* already free */
		}
		/* FALLTHROUGH */
	case AXDR_ENCODE:
	case AXDR_ENCODE_ASYNC:
		if (sp != NULL) {
			size = strlen(sp);
		}
		break;
	case AXDR_DECODE:
	case AXDR_DECODE_ASYNC:
		break;
	case AXDR_STRINGIFY:
		return axdr_str_add_value(xdrs, *cpp);
	default:
		return AXDR_ERROR;
	}

	rval = axdr_async_setup(xdrs, &axdr_string, &cleanup, &state,
				sizeof(*sizep), (void**) &sizep);
	if (rval != AXDR_DONE) {
		return rval;
	}
	
	switch (state) {
	case 0:
		*sizep = size;
		state = 1;
		/* fall through */
	case 1:
		rval = axdr_u_int(xdrs, sizep);
		if (rval != AXDR_DONE) {
			goto out;
		}
		if (*sizep > maxsize) {
			rval = AXDR_ERROR;
			goto out;
		}
		nodesize = *sizep + 1;

		/*
		 * now deal with the actual bytes
		 */
		switch (xdrs->x_op) {
		case AXDR_DECODE:
		case AXDR_DECODE_ASYNC:
			if (nodesize == 0) {
				rval = AXDR_DONE;
				break;
			}
			if (sp == NULL) {
				*cpp = sp = mem_alloc(nodesize);
			}
			if (sp == NULL) {
				warnx("xdr_string: %s", strerror(errno));
				rval = AXDR_ERROR;
				goto out;
			}
			sp[*sizep] = 0;
			/* FALLTHROUGH */
		case AXDR_ENCODE:
		case AXDR_ENCODE_ASYNC:
			rval = AXDR_WAITING;
			break;
		case AXDR_FREE:
			mem_free(sp, nodesize);
			*cpp = NULL;
			rval = AXDR_DONE;
			break;
		case AXDR_STRINGIFY:
			rval = AXDR_ERROR;
			goto out;
		}

		if (rval == AXDR_DONE) {
			break;
		}

		state = 2;
		/* fallthrough */
	case 2:
		rval = axdr_opaque(xdrs, sp, *sizep);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 3;
		break; /* done */
	default:
		rval = AXDR_ERROR;
	}

out:
	axdr_async_teardown(xdrs, &axdr_string, state, cleanup, rval);
	return rval;
}

/* 
 * Wrapper for xdr_string that can be called directly from 
 * routines like clnt_call
 */
axdr_ret_t
axdr_wrapstring(axdr_state_t *xdrs, char **cpp)
{
	return axdr_string(xdrs, cpp, LASTUNSIGNED);
}

/*
 * NOTE: xdr_hyper(), xdr_u_hyper(), xdr_longlong_t(), and xdr_u_longlong_t()
 * are in the "non-portable" section because they require that a `long long'
 * be a 64-bit type.
 *
 *	--thorpej@netbsd.org, November 30, 1999
 */

/*
 * XDR 64-bit integers
 */
axdr_ret_t
axdr_int64_t(axdr_state_t *xdrs, int64_t *llp)
{
	axdr_ret_t	rval;
	bool_t		cleanup;
	int64_t		data;
	int64_t		*datap = &data;
	uint32_t	u32;
	int		state;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		state = 0;
		break;
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		state = 2;
		break;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[16];
		snprintf(buf, sizeof(buf), RPC_INT64_FMT, *llp);
		return axdr_str_add_value(xdrs, buf);
	}
	default:
		return AXDR_ERROR;
	}

	rval = axdr_async_setup(xdrs, &axdr_int64_t, &cleanup, &state,
				sizeof(*datap), (void**) &datap);
	if (rval != AXDR_DONE) {
		return rval;
	}

	switch (state) {
	case 0:
		/* encode first 32 bits */
		u32 = (uint32_t)(((u_int64_t)*llp >> 32) & 0xffffffff);
		rval = axdr_putunit(xdrs, (int32_t *)&u32);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 1;
		/* fallthrough */
	case 1:
		/* encode second 32 bits */
		u32 = (uint32_t)(((u_int64_t)*llp) & 0xffffffff);
		rval = axdr_putunit(xdrs, (int32_t *)&u32);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 4;
		break; /* done */
	case 2:
		/* decode first 32 bits */
		*datap = 0LL;
		rval = axdr_getunit(xdrs, (int32_t *)&u32);
		if (rval != AXDR_DONE) {
			goto out;
		}
		*datap = (int64_t)(((u_int64_t)u32) << 32);
		state = 3;
		/* fallthrough */
	case 3:
		/* decode second 32 bits */
		rval = axdr_getunit(xdrs, (int32_t *)&u32);
		if (rval != AXDR_DONE) {
			goto out;
		}
		*datap |= (int64_t)((u_int64_t)u32);
		*llp = *datap;
		state = 4;
		break; /* done */
	default:
		rval = AXDR_ERROR;
	}

out:
	axdr_async_teardown(xdrs, &axdr_int64_t, state, cleanup, rval);
	return rval;
}


/*
 * XDR unsigned 64-bit integers
 */
axdr_ret_t
axdr_u_int64_t(axdr_state_t *xdrs, u_int64_t *u64p)
{
	axdr_ret_t	rval;
	bool_t		cleanup;
	u_int64_t	data;
	u_int64_t	*datap = &data;
	uint32_t	u32;
	int		state;

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		state = 0;
		break;
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		state = 2;
		break;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[16];

		snprintf(buf, sizeof(buf), RPC_UINT64_FMT, *u64p);
		return axdr_str_add_value(xdrs, buf);
	}
	default:
		return AXDR_ERROR;
	}

	rval = axdr_async_setup(xdrs, &axdr_u_int64_t, &cleanup, &state,
				sizeof(*datap), (void**) &datap);
	if (rval != AXDR_DONE) {
		return rval;
	}

	switch (state) {
	case 0:
		/* encode first 32 bits */
		u32 = (uint32_t)((*u64p >> 32) & 0xffffffff);
		rval = axdr_putunit(xdrs, (int32_t *)&u32);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 1;
		/* fallthrough */
	case 1:
		/* encode second 32 bits */
		u32 = (uint32_t)((*u64p) & 0xffffffff);
		rval = axdr_putunit(xdrs, (int32_t *)&u32);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 4;
		break; /* done */
	case 2:
		/* decode first 32 bits */
		*datap = 0ULL;
		rval = axdr_getunit(xdrs, (int32_t *)&u32);
		if (rval != AXDR_DONE) {
			goto out;
		}
		*datap = ((u_int64_t)u32) << 32;
		state = 3;
		/* fallthrough */
	case 3:
		/* decode second 32 bits */
		rval = axdr_getunit(xdrs, (int32_t *)&u32);
		if (rval != AXDR_DONE) {
			goto out;
		}
		*datap |= (u_int64_t)u32;
		*u64p = *datap;
		state = 4;
		break; /* done */
	default:
		rval = AXDR_ERROR;
	}

out:
	axdr_async_teardown(xdrs, &axdr_u_int64_t, state, cleanup, rval);
	return rval;
}

/*
 * XDR POSIX uint64
 */
axdr_ret_t
axdr_uint64_t(axdr_state_t *xdrs, uint64_t *u64p)
{
	return axdr_u_int64_t(xdrs, u64p);
}


/*
 * XDR hypers
 */
axdr_ret_t
axdr_hyper(axdr_state_t *xdrs, longlong_t *llp)
{

	/*
	 * Don't bother open-coding this; it's a fair amount of code.  Just
	 * call xdr_int64_t().
	 */
	return (axdr_int64_t(xdrs, llp));
}


/*
 * XDR unsigned hypers
 */
axdr_ret_t
axdr_u_hyper(axdr_state_t *xdrs, u_longlong_t *u64p)
{

	/*
	 * Don't bother open-coding this; it's a fair amount of code.  Just
	 * call xdr_u_int64_t().
	 */
	return (axdr_u_int64_t(xdrs, u64p));
}


/*
 * XDR longlong_t's
 */
axdr_ret_t
axdr_longlong_t(axdr_state_t *xdrs, longlong_t *llp)
{
	/*
	 * Don't bother open-coding this; it's a fair amount of code.  Just
	 * call xdr_int64_t().
	 */
	return (axdr_int64_t(xdrs, llp));
}


/*
 * XDR u_longlong_t's
 */
axdr_ret_t
axdr_u_longlong_t(axdr_state_t *xdrs, u_longlong_t *ullp)
{
	/*
	 * Don't bother open-coding this; it's a fair amount of code.  Just
	 * call xdr_u_int64_t().
	 */
	return (axdr_u_int64_t(xdrs, ullp));
}

/*
 * XDR off_t
 */
axdr_ret_t
axdr_off_t(axdr_state_t *xdrs, off_t *offp)
{
	int64_t    i64;
	axdr_ret_t rval;

	/* Always send across the wire as 64-bits */
	i64 = *offp;
	rval = axdr_int64_t(xdrs, &i64);
	*offp = (off_t) i64;

	return rval;
}

/*
 * XDR size_t
 */
axdr_ret_t
axdr_size_t(axdr_state_t *xdrs, size_t *sizep)
{
	u_int64_t  u64;
	axdr_ret_t rval;

	/* Always send across the wire as 64-bits */
	u64 = *sizep;
	rval = axdr_u_int64_t(xdrs, &u64);
	*sizep = (size_t) u64;

	return rval;
}

/*
 * XDR time_t
 */
axdr_ret_t
axdr_time_t(axdr_state_t *xdrs, time_t *timep)
{
	int64_t    i64;
	axdr_ret_t rval;

	/* Always send across the wire as 64-bits */
	i64 = *timep;
	rval = axdr_int64_t(xdrs, &i64);
	*timep = (time_t) i64;
}
   

axdr_ret_t
axdr_element(axdr_state_t *xdrs, const char *name, bool_t first,
	     axdrproc_t proc, void *where, int *offp)
{
	axdr_ret_t rval;

	if (xdrs->x_op == AXDR_STRINGIFY) {
		rval = axdr_str_set_name(xdrs, name, first, offp);
		if (rval != AXDR_DONE) {
			return rval;
		}
	}

	return (*proc)(xdrs, where);
}


axdr_ret_t
axdr_control_default(axdr_state_t *xdrs, axdr_cmd_t cmd, void *arg)
{
	/* currently, no default ops supported */
	return AXDR_ERROR;
}

axdr_ret_t
axdr_control(axdr_state_t *xdrs, axdr_cmd_t cmd, void *arg)
{
	const axdr_ops_t *x_ops;

	if (!xdrs) {
		return AXDR_ERROR;
	}
	x_ops = xdrs->x_ops;
	if (!x_ops) {
		return AXDR_ERROR;
	}
	if (!x_ops->x_control) {
		return axdr_control_default(xdrs, cmd, arg);
	}

	return (*x_ops->x_control)(xdrs, cmd, arg);
}
