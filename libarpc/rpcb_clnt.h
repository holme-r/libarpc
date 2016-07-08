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
 * Copyright (c) 1986 - 1991 by Sun Microsystems, Inc.
 */

/*
 * rpcb_clnt.h
 * Supplies C routines to get to rpcbid services.
 *
 */

/*
 * Usage:
 *	success = rpcb_set(program, version, nconf, address);
 *	success = rpcb_unset(program, version, nconf);
 *	success = rpcb_getaddr(program, version, nconf, host);
 *	head = rpcb_getmaps(nconf, host);
 *	clnt_stat = rpcb_rmtcall(nconf, host, program, version, procedure,
 *		xdrargs, argsp, xdrres, resp, tout, addr_ptr)
 *	success = rpcb_gettime(host, timep)
 *	uaddr = rpcb_taddr2uaddr(nconf, taddr);
 *	taddr = rpcb_uaddr2uaddr(nconf, uaddr);
 */

#ifndef _LIBARPC_RPCB_CLNT_H
#define	_LIBARPC_RPCB_CLNT_H

#include <libarpc/types.h>

__BEGIN_DECLS

/* new async interfaces for things.
 * FIXME: not everything has an async interface.
 */
typedef struct arpcb_client_s *arpcb_client_t;

typedef void (*arpcb_findaddr_fn_t)(arpcb_client_t, void *arg, 
				    arpc_createerr_t *errp, 
				    const arpc_addr_t *);
typedef void (*arpcb_clnt_fn_t)(arpcb_client_t, void *arg, 
				arpc_createerr_t *errp, ar_client_t *clnt);
                                    
extern int arpcb_findaddr_create(ar_ioctx_t, const arpcprog_t,
				 const arpcvers_t, const char *netid, 
				 const char *, arpcb_findaddr_fn_t, void *,
				 const struct timespec *, 
				 arpc_createerr_t *, arpcb_client_t *);

extern int arpcb_clnt_create(ar_ioctx_t, const char *netid, const char *, 
			     arpcb_clnt_fn_t, void *, 
			     const struct timespec *, arpc_createerr_t *,
			     arpcb_client_t *);

extern void arpcb_clnt_destroy(arpcb_client_t);

struct rpcblist *arpcb_getmaps(ar_ioctx_t, const char *netid, 
			       const char *host, 
			       arpc_createerr_t *errp);
ar_stat_t arpcb_rmtcall(ar_ioctx_t ctx, const char *netid, const char *host,
			arpcprog_t prog, arpcvers_t vers, 
			arpcproc_t proc, axdrproc_t xdrargs, 
			caddr_t argsp, axdrproc_t xdrres,
			caddr_t resp, struct timeval tout, 
			const arpc_addr_t *addr_ptr, 
			arpc_createerr_t *errp);


__END_DECLS

#endif	/* !_LIBARPC_RPCB_CLNT_H */
