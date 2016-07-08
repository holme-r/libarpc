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
 * xdr_float.c, Generic XDR routines implementation.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * These are the "floating point" xdr routines used to (de)serialize
 * most common data items.  See xdr.h for more info on the interface to
 * xdr.
 */

#include "compat.h"

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>

#include <libarpc/arpc.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>

/*
 * NOTE: according to the GNU autoconf manual it is safe to assume
 * IEEE-754 floating point.  (Autoconf does not provide dynamic checks
 * for IEEE-754)...
 */

#include <sys/socket.h>
#include <netinet/in.h>
#define IEEEFP 1

#if defined(__vax__)

/* What IEEE single precision floating point looks like on a Vax */
struct	ieee_single {
	unsigned int	mantissa: 23;
	unsigned int	exp	 : 8;
	unsigned int	sign	 : 1;
};

/* Vax single precision floating point */
struct	vax_single {
	unsigned int	mantissa1 : 7;
	unsigned int	exp	  : 8;
	unsigned int	sign	  : 1;
	unsigned int	mantissa2 : 16;
};

#define VAX_SNG_BIAS	0x81
#define IEEE_SNG_BIAS	0x7f

static struct sgl_limits {
	struct vax_single s;
	struct ieee_single ieee;
} sgl_limits[2] = {
	{{ 0x7f, 0xff, 0x0, 0xffff },	/* Max Vax */
	{ 0x0, 0xff, 0x0 }},		/* Max IEEE */
	{{ 0x0, 0x0, 0x0, 0x0 },	/* Min Vax */
	{ 0x0, 0x0, 0x0 }}		/* Min IEEE */
};
#endif /* vax */

axdr_ret_t 
axdr_float(axdr_state_t *xdrs, float *fp)
{
#ifndef IEEEFP
	axdr_ret_t	rval;
	struct ieee_single is;
	struct vax_single vs, *vsp;
	struct sgl_limits *lim;
	int i;
#endif

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
#ifdef IEEEFP
		return (axdr_putint32(xdrs, (int32_t *)fp));
#else
		vs = *((struct vax_single *)fp);
		for (i = 0, lim = sgl_limits;
			i < sizeof(sgl_limits)/sizeof(struct sgl_limits);
			i++, lim++) {
			if ((vs.mantissa2 == lim->s.mantissa2) &&
				(vs.exp == lim->s.exp) &&
				(vs.mantissa1 == lim->s.mantissa1)) {
				is = lim->ieee;
				goto shipit;
			}
		}
		is.exp = vs.exp - VAX_SNG_BIAS + IEEE_SNG_BIAS;
		is.mantissa = (vs.mantissa1 << 16) | vs.mantissa2;
	shipit:
		is.sign = vs.sign;
		return (axdr_putint32(xdrs, (int32_t *)&is));
#endif
	case AXDR_DECODE:
	case AXDR_DECODE_ASYNC:
#ifdef IEEEFP
		return (axdr_getint32(xdrs, (int32_t *)fp));
#else
		vsp = (struct vax_single *)fp;
		rval = axdr_getint32(xdrs, (int32_t *)&is);
		for (i = 0, lim = sgl_limits;
			i < sizeof(sgl_limits)/sizeof(struct sgl_limits);
			i++, lim++) {
			if ((is.exp == lim->ieee.exp) &&
				(is.mantissa == lim->ieee.mantissa)) {
				*vsp = lim->s;
				goto doneit;
			}
		}
		vsp->exp = is.exp - IEEE_SNG_BIAS + VAX_SNG_BIAS;
		vsp->mantissa2 = is.mantissa;
		vsp->mantissa1 = (is.mantissa >> 16);
	doneit:
		vsp->sign = is.sign;
		return rval;
#endif
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[32];
		snprintf(buf, sizeof(buf), "%f", (double)*fp);
		return axdr_str_add_value(xdrs, buf);
	}
	}
	/* NOTREACHED */
	return AXDR_ERROR;
}

#if defined(__vax__)
/* What IEEE double precision floating point looks like on a Vax */
struct	ieee_double {
	unsigned int	mantissa1 : 20;
	unsigned int	exp	   : 11;
	unsigned int	sign	  : 1;
	unsigned int	mantissa2 : 32;
};

/* Vax double precision floating point */
struct  vax_double {
	unsigned int	mantissa1 : 7;
	unsigned int	exp	   : 8;
	unsigned int	sign	  : 1;
	unsigned int	mantissa2 : 16;
	unsigned int	mantissa3 : 16;
	unsigned int	mantissa4 : 16;
};

#define VAX_DBL_BIAS	0x81
#define IEEE_DBL_BIAS	0x3ff
#define MASK(nbits)	((1 << nbits) - 1)

static struct dbl_limits {
	struct	vax_double d;
	struct	ieee_double ieee;
} dbl_limits[2] = {
	{{ 0x7f, 0xff, 0x0, 0xffff, 0xffff, 0xffff },	/* Max Vax */
	{ 0x0, 0x7ff, 0x0, 0x0 }},			/* Max IEEE */
	{{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},		/* Min Vax */
	{ 0x0, 0x0, 0x0, 0x0 }}				/* Min IEEE */
};

#endif /* vax */


axdr_ret_t
axdr_double(axdr_state_t *xdrs, double *dp)
{
	axdr_ret_t	rval;
	bool_t		cleanup;
	int		state;
	int32_t		tval;
	int32_t		*tptr = &tval;
	int32_t		t32;
	u_int64_t	*ptr64;
#ifndef IEEEFP
	int32_t *lp;
	struct ieee_double id;
	struct vax_double vd;
	struct dbl_limits *lim;
	int i;
#endif

	switch (xdrs->x_op) {
	case AXDR_ENCODE_ASYNC:
	case AXDR_ENCODE:
		state = 0;
#ifndef IEEEFP
		vd = *((struct vax_double *)dp);
		for (i = 0, lim = dbl_limits;
			i < sizeof(dbl_limits)/sizeof(struct dbl_limits);
			i++, lim++) {
			if ((vd.mantissa4 == lim->d.mantissa4) &&
				(vd.mantissa3 == lim->d.mantissa3) &&
				(vd.mantissa2 == lim->d.mantissa2) &&
				(vd.mantissa1 == lim->d.mantissa1) &&
				(vd.exp == lim->d.exp)) {
				id = lim->ieee;
				goto shipit;
			}
		}
		id.exp = vd.exp - VAX_DBL_BIAS + IEEE_DBL_BIAS;
		id.mantissa1 = (vd.mantissa1 << 13) | (vd.mantissa2 >> 3);
		id.mantissa2 = ((vd.mantissa2 & MASK(3)) << 29) |
				(vd.mantissa3 << 13) |
				((vd.mantissa4 >> 3) & MASK(13));
	shipit:
		id.sign = vd.sign;
#endif /* !IEEEFP */
		break;
	case AXDR_DECODE_ASYNC:
	case AXDR_DECODE:
		state = 2;
		break;
	case AXDR_FREE:
		return AXDR_DONE;
	case AXDR_STRINGIFY: {
		char buf[32];
		snprintf(buf, sizeof(buf), "%f", *dp);
		return axdr_str_add_value(xdrs, buf);
	}
	default:
		return AXDR_ERROR;
	}

	rval = axdr_async_setup(xdrs, &axdr_double, &cleanup, &state,
				   sizeof(*tptr), (void **)&tptr);
	if (rval != AXDR_DONE) {
		return rval;
	}

	switch (state) {
	case 0:
		/* encode first 32 bits */
#ifdef IEEEFP
		ptr64 = (u_int64_t *)dp;
		t32 = (int32_t)((*ptr64) >> 32) & 0xffffffff;
#else
		lp = (int32_t *)&id;
		t32 = lp[0];
#endif	
		rval = axdr_putint32(xdrs, &t32);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 1;
		/* fallthrough */
	case 1:
		/* encode second 32 bits */
#ifdef IEEEFP
		ptr64 = (u_int64_t *)dp;
		t32 = (int32_t)(*ptr64) & 0xffffffff;
#else
		lp = (int32_t *)&id;
		t32 = lp[1];
#endif	
		rval = axdr_putint32(xdrs, &t32);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 4;
		break; /* done */
	case 2:
		/* decode first 32 bits */
		/* NOTE: relying on full value returned in last call */
		rval = axdr_getint32(xdrs, tptr);
		if (rval != AXDR_DONE) {
			goto out;
		}
		state = 3;
		/* fallthrough */
	case 3:
		/* decode second 32 bits */
		rval = axdr_getint32(xdrs, &t32);
		if (rval != AXDR_DONE) {
			goto out;
		}
#ifdef IEEEFP
		*tptr |= (u_int64_t)t32;
		*((u_int64_t *)dp) = ((((u_int64_t)(*tptr)) << 32) | 
				      (u_int64_t)t32);
#else /* IEEEFP */
		lp = (int32_t *)&id;
		lp[0] = *tptr;
		lp[1] = t32;

		for (i = 0, lim = dbl_limits;
			i < sizeof(dbl_limits)/sizeof(struct dbl_limits);
			i++, lim++) {
			if ((id.mantissa2 == lim->ieee.mantissa2) &&
				(id.mantissa1 == lim->ieee.mantissa1) &&
				(id.exp == lim->ieee.exp)) {
				vd = lim->d;
				goto doneit;
			}
		}
		vd.exp = id.exp - IEEE_DBL_BIAS + VAX_DBL_BIAS;
		vd.mantissa1 = (id.mantissa1 >> 13);
		vd.mantissa2 = ((id.mantissa1 & MASK(13)) << 3) |
				(id.mantissa2 >> 29);
		vd.mantissa3 = (id.mantissa2 >> 13);
		vd.mantissa4 = (id.mantissa2 << 3);
	doneit:
		vd.sign = id.sign;
		*dp = *((double *)&vd);
#endif /* !IEEEFP */
		break; /* done */
	default:
		rval = AXDR_ERROR;
	}

out:
	axdr_async_teardown(xdrs, &axdr_double, state, cleanup, rval);
	return rval;
}
