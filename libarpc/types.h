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
 *
 *	from: @(#)types.h 1.18 87/07/24 SMI
 *	from: @(#)types.h	2.3 88/08/15 4.0 RPCSRC
 * $FreeBSD: src/include/rpc/types.h,v 1.10.6.1 2003/12/18 00:59:50 peter Exp $
 */

/*
 * Rpc additions to <sys/types.h>
 */
#ifndef _ARPC_TYPES_H
#define _ARPC_TYPES_H

#include <sys/types.h>
#include <stdint.h>

typedef int32_t bool_t;
typedef int32_t enum_t;

typedef u_int32_t arpcprog_t;
typedef u_int32_t arpcvers_t;
typedef u_int32_t arpcproc_t;
typedef u_int32_t arpcprot_t;
typedef u_int32_t arpcport_t;
typedef   int32_t arpc_inline_t;

#define __dontcare__	-1

#ifndef FALSE
#	define FALSE	(0)
#endif
#ifndef TRUE
#	define TRUE	(1)
#endif

#define mem_alloc(bsize)	calloc(1, bsize)
#define mem_free(ptr, bsize)	free(ptr)

#include <sys/time.h>

typedef struct arpc_addr_s {
	unsigned int	maxlen;
	unsigned int	len;
	char		* buf;
} arpc_addr_t;

struct ssl_ctx_st;
struct x509_store_ctx_st;
struct ssl_st;

typedef int (*ar_tls_setup_cb_t)(void *arg, struct ssl_ctx_st *ctx,
				 bool_t *do_verifyp);
typedef int (*ar_tls_verify_cb_t)(void *arg, int preverify_ok,
				  struct x509_store_ctx_st *ctx);
typedef void (*ar_tls_info_cb_t)(void *arg, const struct ssl_st *ssl, 
				 int where, int ret);

#endif /* !_ARPC_TYPES_H */
