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
 * rpc.h, Just includes the billions of rpc header files necessary to
 * do remote procedure calling.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */
#ifndef _LIBARPC_ARPC_H
#define _LIBARPC_ARPC_H

#include <libarpc/types.h>		/* some typedefs */
#include <sys/socket.h>
#include <netinet/in.h>

/* external data representation interfaces */
#include <libarpc/axdr.h>		/* generic (de)serializer */

/* Common io substrate and context. Also, connection abstraction layer */
#include <libarpc/arpc_io.h>

/* Client side only authentication */
#include <libarpc/auth.h>		/* generic authenticator (client side) */

/* Client side (mostly) remote procedure call */
#include <libarpc/clnt.h>		/* generic rpc stuff */

/* semi-private protocol headers */
#include <libarpc/arpc_msg.h>	/* protocol for rpc messages */
#include <libarpc/auth_unix.h>	/* protocol for unix style cred */
/*
 *  Uncomment-out the next line if you are building the rpc library with
 *  DES Authentication (see the README file in the secure_rpc/ directory).
 */
#include <libarpc/auth_des.h>	/* protocol for des style cred */

/* Server side only remote procedure callee */
#include <libarpc/svc.h>		/* service manager and multiplexer */
#include <libarpc/svc_auth.h>	/* service side authenticator */

/* Portmapper client, server, and protocol headers */
#include <libarpc/pmap_clnt.h>
#include <libarpc/rpcb_clnt.h>	/* rpcbind interface functions */
#include <libarpc/arpcent.h>

#include <libarpc/stat.h>

/* NOTE: these map to 'semantics' RPC bind wire values, don't change */
#define AR_SEM_CLTS	1
#define AR_SEM_COTS	3

typedef struct ar_netid_s {
	const char 		*an_netid;
	sa_family_t		an_family;
	int			an_semantics;
	int			an_proto;
	const char		*an_familyname;
	const char		*an_protoname;
	struct ar_netid_s	*an_next;
} ar_netid_t;

typedef struct ar_sockinfo_s {
	sa_family_t si_af; 
        int si_proto;
        int si_socktype;
        int si_alen;
} ar_sockinfo_t;

struct ar_ioctx_s;

extern int ar_str2netid(struct ar_ioctx_s *ioctx, const char *netid, 
			ar_netid_t **infop);
extern int ar_idx2netid(struct ar_ioctx_s *ioctx, int idx, ar_netid_t **infop);
extern int ar_class2netidstr(struct ar_ioctx_s *ioctx, 
			     int semantics, sa_family_t,
			     const char **netid);
extern int ar_taddr2uaddr(struct ar_ioctx_s *ioctx, const char *netid, 
			  const arpc_addr_t *addr, char **retp);
extern int ar_taddr2uaddr_af(sa_family_t af, const arpc_addr_t *nbuf,
			     char **retp);
extern int ar_uaddr2taddr(struct ar_ioctx_s *ioctx, const char *netid, 
			  const char *uaddr, arpc_addr_t **retp);
extern void ar_errno2err(arpc_err_t *errp, int err);
extern int ar_uaddr2taddr_af(int af, const char *uaddr, arpc_addr_t **retp);
extern int ar_fd2sockinfo(int fd, ar_sockinfo_t *sip);
extern int ar_str2sockinfo(struct ar_ioctx_s *ioctx, const char *netid,
			   ar_sockinfo_t *sip);
extern int ar_netid2sockinfo(const ar_netid_t *, ar_sockinfo_t *sip);
extern int ar_sockisbound(int fd, bool_t *bound);

#endif /* !_LIBARPC_ARPC_H */
