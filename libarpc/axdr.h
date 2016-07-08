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
 * xdr.h, External Data Representation Serialization Routines.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#ifndef _ARPC_XDR_H
#define _ARPC_XDR_H

#include <sys/cdefs.h>
#include <sys/types.h>
#include <libarpc/types.h>
#include <stdint.h>
#include <stdio.h>

/*
 * XDR provides a conventional way for converting between C data
 * types and an external bit-string representation.  Library supplied
 * routines provide for the conversion on built-in C data types.  These
 * routines and utility routines defined here are used to help implement
 * a type encode/decode routine for each user-defined type.
 *
 * Each data type provides a single procedure which takes two arguments:
 *
 *	bool_t
 *	xdrproc(xdrs, argresp)
 *		XDR *xdrs;
 *		<type> *argresp;
 *
 * xdrs is an instance of a XDR handle, to which or from which the data
 * type is to be converted.  argresp is a pointer to the structure to be
 * converted.  The XDR handle contains an operation field which indicates
 * which of the operations (ENCODE, DECODE, ENCODE_ASYNC, 
 * DECODE_ASYNC, FREE, or STRINGIFY) is to be performed.
 *
 * XDR_DECODE/XDR_DECODE_ASYNC may allocate space if the pointer 
 * argresp is null.  This data can be freed with the XDR_FREE operation.
 *
 * We write only one procedure per data type to make it easy
 * to keep the encode and decode procedures for a data type consistent.
 * In many cases the same code performs all operations on a user defined type,
 * because all the hard work is done in the component type routines.
 * decode as a series of calls on the nested data types.
 */

/*
 * Xdr operations.  XDR_ENCODE causes the type to be encoded into the
 * stream.  XDR_DECODE causes the type to be extracted from the stream.
 * XDR_FREE can be used to release the space allocated by an XDR_DECODE
 * request.
 */
enum axdr_op_e {
	AXDR_ENCODE=0,
	AXDR_DECODE=1,
	AXDR_FREE=2,
	AXDR_ENCODE_ASYNC=3,
	AXDR_DECODE_ASYNC=4,
	AXDR_STRINGIFY=5
};

enum axdr_ret_e {
	AXDR_ERROR=0,
	AXDR_DONE=1,
	AXDR_WAITING=2
};

enum axdr_cmd_e {
	AR_XDRGET_EOR = 1, 	/* bool_t, returns true if at eor */
	AR_XDRGET_AVAIL = 2, 	/* off_t, returns buffered data byte count */
};

typedef enum axdr_ret_e axdr_ret_t;
typedef enum axdr_op_e axdr_op_t;
typedef enum axdr_cmd_e axdr_cmd_t;

/*
 * This is the number of bytes per unit of external data.
 */
#define BYTES_PER_XDR_UNIT	(4)
#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
		   * BYTES_PER_XDR_UNIT)

struct axdr_state_s;
typedef struct axdr_state_s axdr_state_t;


struct axdr_ops_s {
	/* get a long from underlying stream */
	axdr_ret_t	(*x_getunit)(axdr_state_t *, int32_t *);
	/* put a long to " */
	axdr_ret_t	(*x_putunit)(axdr_state_t *, const int32_t *);
	/* get some bytes from " */
	axdr_ret_t	(*x_getbytes)(axdr_state_t *, char *, size_t);
	/* put some bytes to " */
	axdr_ret_t	(*x_putbytes)(axdr_state_t *, const char *, size_t);
	/* returns bytes off from beginning */
	off_t		(*x_getpostn)(axdr_state_t *);
	/* lets you reposition the stream */
	axdr_ret_t  	(*x_setpostn)(axdr_state_t *, off_t);
	/* buf quick ptr to buffered data */
	int32_t 	*(*x_inline)(axdr_state_t *, size_t);
	/* free privates of this xdr_stream */
	void		(*x_destroy)(axdr_state_t *);
	axdr_ret_t	(*x_control)(axdr_state_t *, axdr_cmd_t, void *);
	axdr_ret_t	(*x_str_set_name)(axdr_state_t *, const char *name, 
					  bool_t first, int *offp);
	axdr_ret_t	(*x_str_add_value)(axdr_state_t *, const char *str);
	axdr_ret_t	(*x_str_add_bin)(axdr_state_t *, 
					 const char *cp, int len);
};

typedef struct axdr_ops_s axdr_ops_t;

/*
 * The XDR state handle.
 * Contains operation which is being applied to the stream,
 * an operations vector for the particular implementation (e.g. see xdr_mem.c),
 * a private field for the use of the particular implementation, and 
 * a field for the use of the caller.
 */

struct astk_s;

struct axdr_state_s {
	axdr_op_t	x_op;		/* operation; fast additional param */
	const axdr_ops_t *x_ops;
	char *	 	x_public;	/* users' data */
	void *		x_private;	/* pointer to private data */
	char * 		x_base;		/* private used for position info */
	off_t		x_handy;	/* extra private value */
	struct astk_s	*x_async;	/* handle for async state */
};


#define MAX_NETOBJ_SZ 1024
struct netobj_s {
	u_int	n_len;
	char	*n_bytes;
};
typedef struct netobj_s netobj_t;


/*
 * A axdrproc_t exists for each data type which is to be encoded or decoded.
 *
 * The second argument to the axdrproc_t is a pointer to an opaque pointer.
 * The opaque pointer generally points to a structure of the data type
 * to be decoded.  If this pointer is 0, then the type routines should
 * allocate dynamic storage of the appropriate size and return it.
 */
typedef	axdr_ret_t (*axdrproc_t)(axdr_state_t *, void *);

/*
 * Operations defined on an axdr_state_t handle
 *
 */
#define axdr_getunit(xdrs, i32p)			\
	(*(xdrs)->x_ops->x_getunit)(xdrs, i32p)

#define axdr_putunit(xdrs, i32p)			\
	(*(xdrs)->x_ops->x_putunit)(xdrs, i32p)

#define axdr_str_add_value(xdrs, str)			\
	(*(xdrs)->x_ops->x_str_add_value)(xdrs, str)

#define axdr_str_set_name(xdrs, name, first, curoffp)	\
	(*(xdrs)->x_ops->x_str_set_name)(xdrs, name, first, curoffp)

/*@unused@*/
static inline axdr_ret_t
axdr_getint32(axdr_state_t *xdrs, int32_t *ip)
{
	return axdr_getunit(xdrs, ip);
}

/*@unused@*/
static inline axdr_ret_t
axdr_putint32(axdr_state_t *xdrs, int32_t *ip)
{
	return axdr_putunit(xdrs, ip);
}

/* FIXME: these should become functions */
#define axdr_getbytes(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)

#define axdr_putbytes(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)

#define axdr_getpos(xdrs)				\
	(*(xdrs)->x_ops->x_getpostn)(xdrs)

#define axdr_setpos(xdrs, pos)				\
	(*(xdrs)->x_ops->x_setpostn)(xdrs, pos)

#define	axdr_inline(xdrs, len)				\
	(*(xdrs)->x_ops->x_inline)(xdrs, len)

#define	axdr_destroy(xdrs)				\
	if ((xdrs)->x_ops->x_destroy) 			\
		(*(xdrs)->x_ops->x_destroy)(xdrs)

axdr_ret_t axdr_control(axdr_state_t *xdrs, axdr_cmd_t cmd, void *arg);

/*
 * Support struct for discriminated unions.
 * You create an array of xdrdiscrim structures, terminated with
 * an entry with a null procedure pointer.  The xdr_union routine gets
 * the discriminant value and then searches the array of structures
 * for a matching value.  If a match is found the associated xdr routine
 * is called to handle that part of the union.  If there is
 * no match, then a default routine may be called.
 * If there is no match and no default routine it is an error.
 */
#define NULL_axdrproc_t ((axdrproc_t)0)
struct axdr_discrim {
	int		value;
	axdrproc_t 	proc;
	const char 	*name;
};
typedef struct axdr_discrim axdr_discrim_t;

/*
 * In-line routines for fast encode/decode of primitive data types.
 * Caveat emptor: these use single memory cycles to get the
 * data from the underlying buffer, and will fail to operate
 * properly if the data is not aligned.  The standard way to use these
 * is to say:
 *	if ((buf = XDR_INLINE(xdrs, count)) == NULL)
 *		return (AXDR_ERROR);
 *	<<< macro calls >>>
 * where ``count'' is the number of bytes of data occupied
 * by the primitive data types.
 *
 * N.B. and frozen for all time: each data type here uses 4 bytes
 * of external representation.
 */
#define IAXDR_GET_INT32(buf)		((int32_t)ntoh32((u_int32_t)*(buf)++))
#define IAXDR_PUT_INT32(buf, v)		(*(buf)++ =(int32_t)hton32((u_int32_t)v))
#define IAXDR_GET_U_INT32(buf)		((u_int32_t)IAXDR_GET_INT32(buf))
#define IAXDR_PUT_U_INT32(buf, v)	IAXDR_PUT_INT32((buf), ((int32_t)(v)))

#define IAXDR_GET_BOOL(buf)		((bool_t)IAXDR_GET_INT32(buf))
#define IAXDR_GET_ENUM(buf, t)		((t)IAXDR_GET_INT32(buf))

#define IAXDR_PUT_BOOL(buf, v)		IAXDR_PUT_INT32((buf), (v))
#define IAXDR_PUT_ENUM(buf, v)		IAXDR_PUT_INT32((buf), (v))

/*
 * These are the "generic" axdr routines.
 * NOTE: the basic unit of serialized XDR (the unitsize) is 32bits.
 * RFC4506 defines strict definitions of an XDR int as 32bits or a unitsize.
 * The parameters to these xdr functions are host datatypes.  Internally,
 * the functions will truncate if needed.  For example if your host has a
 * 64bit integer type, encoding through xdr_int will ignore the most 
 * significant 32 bits of the value.  Similarly decoding through xdr_int will
 * sign extend for the most significant 32 bits. Types that are smaller
 * than 32bits are transparently mapped to the unitsize.  Because of this,
 * do not rely on anything other than the explicit 64 bytes handling
 * anything more than 32bits correctly.
 */
__BEGIN_DECLS
extern axdr_ret_t	axdr_void(void);
extern axdr_ret_t	axdr_int(axdr_state_t *, int *);
extern axdr_ret_t	axdr_u_int(axdr_state_t *, u_int *);
extern axdr_ret_t	axdr_long(axdr_state_t *, long *);
extern axdr_ret_t	axdr_u_long(axdr_state_t *, u_long *);
extern axdr_ret_t	axdr_short(axdr_state_t *, short *);
extern axdr_ret_t	axdr_u_short(axdr_state_t *, u_short *);
extern axdr_ret_t	axdr_int16_t(axdr_state_t *, int16_t *);
extern axdr_ret_t	axdr_u_int16_t(axdr_state_t *, u_int16_t *);
extern axdr_ret_t	axdr_uint16_t(axdr_state_t *, uint16_t *);
extern axdr_ret_t	axdr_int32_t(axdr_state_t *, int32_t *);
extern axdr_ret_t	axdr_u_int32_t(axdr_state_t *, u_int32_t *);
extern axdr_ret_t	axdr_uint32_t(axdr_state_t *, uint32_t *);
extern axdr_ret_t	axdr_int64_t(axdr_state_t *, int64_t *);
extern axdr_ret_t	axdr_u_int64_t(axdr_state_t *, u_int64_t *);
extern axdr_ret_t	axdr_uint64_t(axdr_state_t *, uint64_t *);
extern axdr_ret_t	axdr_bool(axdr_state_t *, bool_t *);
extern axdr_ret_t	axdr_enum(axdr_state_t *, enum_t *);
extern axdr_ret_t	axdr_array(axdr_state_t *, char **, u_int *, 
				   u_int, u_int, axdrproc_t);
extern axdr_ret_t	axdr_bytes(axdr_state_t *, char **, u_int *, u_int);
extern axdr_ret_t	axdr_encap(axdr_state_t *, axdrproc_t, ...);
extern axdr_ret_t	axdr_opaque(axdr_state_t *, char *, u_int);
extern axdr_ret_t	axdr_string(axdr_state_t *, char **, u_int);
extern axdr_ret_t	axdr_union(axdr_state_t *, enum_t *, char *, 
				   const struct axdr_discrim *, axdrproc_t);
extern axdr_ret_t	axdr_char(axdr_state_t *, char *);
extern axdr_ret_t	axdr_u_char(axdr_state_t *, u_char *);
extern axdr_ret_t	axdr_vector(axdr_state_t *, char *, u_int, u_int, 
				    axdrproc_t);
extern axdr_ret_t	axdr_float(axdr_state_t *, float *);
extern axdr_ret_t	axdr_double(axdr_state_t *, double *);
extern axdr_ret_t	axdr_quadruple(axdr_state_t *, long double *);
extern axdr_ret_t	axdr_reference(axdr_state_t *, char **, u_int, 
				       axdrproc_t);
extern axdr_ret_t	axdr_pointer(axdr_state_t *, char **, 
				     u_int, axdrproc_t);
extern axdr_ret_t	axdr_wrapstring(axdr_state_t *, char **);
extern void		axdr_free(axdrproc_t, void *);
extern axdr_ret_t	axdr_hyper(axdr_state_t *, quad_t *);
extern axdr_ret_t	axdr_u_hyper(axdr_state_t *, u_quad_t *);
extern axdr_ret_t	axdr_longlong_t(axdr_state_t *, quad_t *);
extern axdr_ret_t	axdr_u_longlong_t(axdr_state_t *, u_quad_t *);
extern axdr_ret_t	axdr_async_setup(axdr_state_t *, void *, bool_t *, 
					 int *, size_t, void **);
extern void		axdr_async_teardown(axdr_state_t *, void *, int,
					    bool_t, int);
extern axdr_ret_t 	axdr_element(axdr_state_t *, const char *,
				     bool_t first, axdrproc_t, void *, int *);
extern axdr_ret_t	axdr_netobj(axdr_state_t *, netobj_t *);
extern axdr_ret_t       axdr_off_t(axdr_state_t *, off_t *);
extern axdr_ret_t       axdr_size_t(axdr_state_t *, size_t *);
extern axdr_ret_t       axdr_time_t(axdr_state_t *, time_t *);

/*
 * These are the public routines for the various implementations of
 * xdr streams.
 */
/* XDR using memory buffers */
extern void	axdrmem_create(axdr_state_t *, char *, u_int, axdr_op_t);

/* XDR using stdio library */
extern void	axdrstdio_create(axdr_state_t *, FILE *, axdr_op_t);

typedef int (*axdrrec_iofn_t)(void *, void *, size_t *);

/* XDR pseudo records for tcp */
extern int	axdrrec_create(axdr_state_t *, u_int, u_int, void *,
			       axdrrec_iofn_t, axdrrec_iofn_t);

/* make end of xdr record */
extern axdr_ret_t axdrrec_endofrecord(axdr_state_t *, int);

/* move to beginning of next record */
extern axdr_ret_t axdrrec_skiprecord(axdr_state_t *);

/* consume current record, return if more input */
extern axdr_ret_t axdrrec_eof(axdr_state_t *, bool_t *);

/* true if no more buffered data */
extern axdr_ret_t axdrrec_empty(axdr_state_t *, bool_t *);

/* determine the serialized size of a data value */
unsigned long axdr_sizeof(axdrproc_t func, void *data);

extern int axdr_fprint_create(axdr_state_t *, FILE *fp, const char *prefix);
extern int axdr_snprint_create(axdr_state_t *, char *buf, int len);

__END_DECLS

#endif /* !_ARPC_XDR_H */
