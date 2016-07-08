/*
 * $NetBSD: util.c,v 1.4 2000/08/03 00:04:30 fvdl Exp $
 * $FreeBSD: src/usr.sbin/rpcbind/util.c,v 1.5 2002/10/07 02:56:59 alfred Exp $
 */

/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Frank van der Linden.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <config.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <libarpc/arpc.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "rpcbind.h"

#define	SA2SIN(sa)	((struct sockaddr_in *)(sa))
#define	SA2SINADDR(sa)	(SA2SIN(sa)->sin_addr)
#ifdef INET6
#define	SA2SIN6(sa)	((struct sockaddr_in6 *)(sa))
#define	SA2SIN6ADDR(sa)	(SA2SIN6(sa)->sin6_addr)
#endif

static struct sockaddr_in *local_in4;
#ifdef INET6
static struct sockaddr_in6 *local_in6;
#endif

#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#else


/* XXXX
 * FIXME: either roll functionality into libnmd or wait until installed libc supports it
 */
/* The `getifaddrs' function generates a linked list of these structures.
   Each element of the list describes one network interface.  */
struct ifaddrs
{
  struct ifaddrs *ifa_next;	/* Pointer to the next structure.  */

  char *ifa_name;		/* Name of this network interface.  */
  unsigned int ifa_flags;	/* Flags as from SIOCGIFFLAGS ioctl.  */

  struct sockaddr *ifa_addr;	/* Network address of this interface.  */
  struct sockaddr *ifa_netmask; /* Netmask of this interface.  */
  union
  {
    /* At most one of the following two is valid.  If the IFF_BROADCAST
       bit is set in `ifa_flags', then `ifa_broadaddr' is valid.  If the
       IFF_POINTOPOINT bit is set, then `ifa_dstaddr' is valid.
       It is never the case that both these bits are set at once.  */
    struct sockaddr *ifu_broadaddr; /* Broadcast address of this interface. */
    struct sockaddr *ifu_dstaddr; /* Point-to-point destination address.  */
  } ifa_ifu;
  /* These very same macros are defined by <net/if.h> for `struct ifaddr'.
     So if they are defined already, the existing definitions will be fine.  */
# ifndef ifa_broadaddr
#  define ifa_broadaddr	ifa_ifu.ifu_broadaddr
# endif
# ifndef ifa_dstaddr
#  define ifa_dstaddr	ifa_ifu.ifu_dstaddr
# endif

  void *ifa_data;		/* Address-specific data (may be unused).  */
};


/* Create a linked list of `struct ifaddrs' structures, one for each
   network interface on the host machine.  If successful, store the
   list in *IFAP and return 0.  On errors, return -1 and set `errno'.

   The storage returned in *IFAP is allocated dynamically and can
   only be properly freed by passing it to `freeifaddrs'.  */
int
getifaddrs (struct ifaddrs **__ifap) {
	struct ifaddrs *ifaddr;
	
	ifaddr = (struct ifaddrs *) malloc(sizeof(struct ifaddrs));
	if (ifaddr == NULL) {
		errno = ENOMEM;
		*__ifap = NULL;
		return -1;
	}

	/* Zero the memory for now */
	memset(ifaddr, 0, sizeof(*ifaddr));

	*__ifap = ifaddr;

	fprintf(stderr,
		"Calling getifaddrs (if_addrs.h) not yet implemented!\n");
	
	/* set an error */
	errno = EINVAL;
	return -1;
}

/* Reclaim the storage allocated by a previous `getifaddrs' call.  */
void
freeifaddrs (struct ifaddrs *__ifa) {
	if (__ifa == NULL) {
		return;
	}

	fprintf(stderr,
		"Calling freeifaddrs (if_addrs.h) not yet implemented!\n");

	free(__ifa);
}

#endif

static int bitmaskcmp __P((void *, void *, void *, int));
#ifdef INET6
static void in6_fillscopeid __P((struct sockaddr_in6 *));
#endif

/*
 * For all bits set in "mask", compare the corresponding bits in
 * "dst" and "src", and see if they match. Returns 0 if the addresses
 * match.
 */
static int
bitmaskcmp(void *dst, void *src, void *mask, int bytelen)
{
	int i;
	u_int8_t *p1 = dst, *p2 = src, *netmask = mask;

	for (i = 0; i < bytelen; i++)
		if ((p1[i] & netmask[i]) != (p2[i] & netmask[i]))
			return (1);
	return (0);
}

/*
 * Similar to code in ifconfig.c. Fill in the scope ID for link-local
 * addresses returned by getifaddrs().
 */
#ifdef INET6
static void
in6_fillscopeid(struct sockaddr_in6 *sin6)
{
	u_int16_t ifindex;

        if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
		ifindex = ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
		if (sin6->sin6_scope_id == 0 && ifindex != 0) {
			sin6->sin6_scope_id = ifindex;
			*(u_int16_t *)&sin6->sin6_addr.s6_addr[2] = 0;
		}
	}
}
#endif

/*
 * Find a server address that can be used by `caller' to contact
 * the local service specified by `serv_uaddr'. If `clnt_uaddr' is
 * non-NULL, it is used instead of `caller' as a hint suggesting
 * the best address (e.g. the `r_addr' field of an rpc, which
 * contains the rpcbind server address that the caller used).
 *
 * Returns the best server address as a malloc'd "universal address"
 * string which should be freed by the caller. On error, returns NULL.
 */
char *
addrmerge(arpc_addr_t *caller, const char *serv_uaddr, const char *clnt_uaddr,
	  const char *netid)
{
	struct ifaddrs *ifap, *ifp = NULL, *bestif;
	arpc_addr_t *serv_nbp = NULL, *hint_nbp = NULL, tbuf;
	struct sockaddr *caller_sa, *hint_sa, *ifsa, *ifmasksa, *serv_sa;
	struct sockaddr_storage ss;
	socklen_t len;
	const char *hint_uaddr = NULL;
	char *caller_uaddr = NULL;
	char *ret = NULL;
	int err;

#ifdef ND_DEBUG
	if (debugging)
		fprintf(stderr, "addrmerge(caller, %s, %s, %s\n", serv_uaddr,
		    clnt_uaddr == NULL ? "NULL" : clnt_uaddr, netid);
#endif
	caller_sa = (struct sockaddr *)caller->buf;

	err = ar_taddr2uaddr(rpcbind_ioctx, netid, caller, &caller_uaddr);
	if (err != 0) {
		goto freeit;
	}

	/*
	 * Use `clnt_uaddr' as the hint if non-NULL, but ignore it if its
	 * address family is different from that of the caller.
	 */
	hint_sa = NULL;
	if (clnt_uaddr != NULL) {
		hint_uaddr = clnt_uaddr;
		err = ar_uaddr2taddr(rpcbind_ioctx, netid, 
				     clnt_uaddr, &hint_nbp);
		if (err != 0) {
			goto freeit;
		}
		hint_sa = (struct sockaddr *)hint_nbp->buf;
	}
	if (hint_sa == NULL || hint_sa->sa_family != caller_sa->sa_family) {
		hint_uaddr = caller_uaddr;
		hint_sa = (struct sockaddr *)caller->buf;
	}

#ifdef ND_DEBUG
	if (debugging) {
		fprintf(stderr, "addrmerge: hint %s\n", hint_uaddr);
	}
#endif
	/* Local caller, just return the server address. */
	if (strncmp(caller_uaddr, "0.0.0.0.", 8) == 0 ||
	    strncmp(caller_uaddr, "::.", 3) == 0 || caller_uaddr[0] == '/') {
		ret = strdup(serv_uaddr);
		goto freeit;
	}

	if (getifaddrs(&ifp) < 0) {
		goto freeit;
	}

	/*
	 * Loop through all interfaces. For each interface, see if the
	 * network portion of its address is equal to that of the client.
	 * If so, we have found the interface that we want to use.
	 */
	bestif = NULL;
	for (ifap = ifp; ifap != NULL; ifap = ifap->ifa_next) {
		ifsa = ifap->ifa_addr;
		ifmasksa = ifap->ifa_netmask;

		if (ifsa == NULL || ifsa->sa_family != hint_sa->sa_family ||
		    !(ifap->ifa_flags & IFF_UP)) {
			continue;
		}

		switch (hint_sa->sa_family) {
		case AF_INET:
			/*
			 * If the hint address matches this interface
			 * address/netmask, then we're done.
			 */
			if (!bitmaskcmp(&SA2SINADDR(ifsa),
			    &SA2SINADDR(hint_sa), &SA2SINADDR(ifmasksa),
			    sizeof(struct in_addr))) {
				bestif = ifap;
				goto found;
			}
			break;
		case AF_INET6:
			/*
			 * For v6 link local addresses, if the caller is on
			 * a link-local address then use the scope id to see
			 * which one.
			 */
			in6_fillscopeid(SA2SIN6(ifsa));
			if (IN6_IS_ADDR_LINKLOCAL(&SA2SIN6ADDR(ifsa)) &&
			    IN6_IS_ADDR_LINKLOCAL(&SA2SIN6ADDR(caller_sa)) &&
			    IN6_IS_ADDR_LINKLOCAL(&SA2SIN6ADDR(hint_sa))) {
				if (SA2SIN6(ifsa)->sin6_scope_id ==
				    SA2SIN6(caller_sa)->sin6_scope_id) {
					bestif = ifap;
					goto found;
				}
			} else if (!bitmaskcmp(&SA2SIN6ADDR(ifsa),
			    &SA2SIN6ADDR(hint_sa), &SA2SIN6ADDR(ifmasksa),
			    sizeof(struct in6_addr))) {
				bestif = ifap;
				goto found;
			}
			break;
		default:
			continue;
		}

		/*
		 * Remember the first possibly useful interface, preferring
		 * "normal" to point-to-point and loopback ones.
		 */
		if (bestif == NULL ||
		    (!(ifap->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT)) &&
		     (bestif->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT)))) {
			bestif = ifap;
		}
	}
	if (bestif == NULL) {
		goto freeit;
	}

found:
	/*
	 * Construct the new address using the the address from
	 * `bestif', and the port number from `serv_uaddr'.
	 */
	err = ar_uaddr2taddr(rpcbind_ioctx, netid, serv_uaddr, &serv_nbp);
	if (err != 0) {
		goto freeit;
	}
	serv_sa = (struct sockaddr *)serv_nbp->buf;

	switch (ss.ss_family) {
	case AF_INET:
		len = sizeof(struct sockaddr_in);
		memcpy(&ss, bestif->ifa_addr, len);
		SA2SIN(&ss)->sin_port = SA2SIN(serv_sa)->sin_port;
		break;
	case AF_INET6:
		len = sizeof(struct sockaddr_in6);
		memcpy(&ss, bestif->ifa_addr, len);
		SA2SIN6(&ss)->sin6_port = SA2SIN6(serv_sa)->sin6_port;
		break;
	default:
		memset(&ss, 0, sizeof(ss));
		len = 0;
		break;
	}
	tbuf.len = len;
	tbuf.maxlen = sizeof(ss);
	tbuf.buf = (char *)&ss;
	err = ar_taddr2uaddr(rpcbind_ioctx, netid, &tbuf, &ret);
	if (err != 0) {
		ret = NULL;
	}
freeit:
	if (caller_uaddr != NULL) {
		free(caller_uaddr);
	}
	if (hint_nbp != NULL) {
		if (hint_nbp->buf) {
			free(hint_nbp->buf);
		}
		free(hint_nbp);
	}
	if (serv_nbp != NULL) {
		if (serv_nbp->buf) {
			free(serv_nbp->buf);
		}
		free(serv_nbp);
	}
	if (ifp != NULL) {
		freeifaddrs(ifp);
	}

#ifdef ND_DEBUG
	if (debugging) {
		fprintf(stderr, "addrmerge: returning %s\n", ret);
	}
#endif
	return ret;
}

void
network_init()
{
#ifdef INET6
	struct ifaddrs *ifap, *ifp;
	struct ipv6_mreq mreq6;
	unsigned int ifindex;
	int s;
#endif
	int ecode;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	if ((ecode = getaddrinfo(NULL, "sunrpc", &hints, &res))) {
		if (debugging)
			fprintf(stderr, "can't get local ip4 address: %s\n",
			    gai_strerror(ecode));
	} else {
		local_in4 = (struct sockaddr_in *)malloc(sizeof *local_in4);
		if (local_in4 == NULL) {
			if (debugging)
				fprintf(stderr, "can't alloc local ip4 addr\n");
		}
		memcpy(local_in4, res->ai_addr, sizeof *local_in4);
	}

#ifdef INET6
	hints.ai_family = AF_INET6;
	if ((ecode = getaddrinfo(NULL, "sunrpc", &hints, &res))) {
		if (debugging)
			fprintf(stderr, "can't get local ip6 address: %s\n",
			    gai_strerror(ecode));
	} else {
		local_in6 = (struct sockaddr_in6 *)malloc(sizeof *local_in6);
		if (local_in6 == NULL) {
			if (debugging)
				fprintf(stderr, "can't alloc local ip6 addr\n");
		}
		memcpy(local_in6, res->ai_addr, sizeof *local_in6);
	}

	/*
	 * Now join the RPC ipv6 multicast group on all interfaces.
	 */
	if (getifaddrs(&ifp) < 0) {
		return;
	}

	mreq6.ipv6mr_interface = 0;
	inet_pton(AF_INET6, AR_RPCB_MULTICAST_ADDR, &mreq6.ipv6mr_multiaddr);

	s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	/*
	 * Loop through all interfaces. For each IPv6 multicast-capable
	 * interface, join the RPC multicast group on that interface.
	 */
	for (ifap = ifp; ifap != NULL; ifap = ifap->ifa_next) {
		if (ifap->ifa_addr->sa_family != AF_INET6 ||
		    !(ifap->ifa_flags & IFF_MULTICAST))
			continue;
		ifindex = if_nametoindex(ifap->ifa_name);
		if (ifindex == mreq6.ipv6mr_interface)
			/*
			 * Already did this one.
			 */
			continue;
		mreq6.ipv6mr_interface = ifindex;
		if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6,
		    sizeof mreq6) < 0)
			if (debugging)
				perror("setsockopt v6 multicast");
	}
#endif

	/* close(s); */
}

struct sockaddr *
local_sa(int af, u_int *lenp)
{
	if (!lenp) {
		return NULL;
	}
	switch (af) {
	case AF_INET:
		*lenp = sizeof(struct sockaddr_in);
		return (struct sockaddr *)local_in4;
	case AF_INET6:
		*lenp = sizeof(struct sockaddr_in6);
		return (struct sockaddr *)local_in6;
	default:
		*lenp = 0;
		return NULL;
	}
}

char *
rqst2uaddr(ar_svc_req_t *rqstp)
{
	struct sockaddr_storage iaddr;
	const char *netidstr;
	arpc_addr_t addr;
	char *uaddr;
	int err;

	if (!ar_svc_control(rqstp->rq_xprt,  AR_SVCGET_NETID, &netidstr)) {
		return NULL;
	}

	addr.maxlen = sizeof(iaddr);
	addr.len = sizeof(iaddr);
	addr.buf = (char *)&iaddr;

	if (!ar_svc_control(rqstp->rq_xprt, AR_SVCGET_REMOTE_ADDR, &addr)) {
		return NULL;
	}

	err = ar_taddr2uaddr(rpcbind_ioctx, netidstr, &addr, &uaddr);
	if (err != 0) {
		return NULL;
	}

	return uaddr;
}


static int 
rpcbproc_copy_rpcblistent(rpcblist *orig, rpcblist **newp) 
{
	rpcblist *new;

	if (!orig || !newp) {
		return EINVAL;
	}

	new = malloc(sizeof(*new));
	if (!new) {
		return ENOMEM;
	}

	memset(new, 0, sizeof(*new));
	if (orig->rpcb_map.r_netid) {
		new->rpcb_map.r_netid = strdup(orig->rpcb_map.r_netid);
		if (!new->rpcb_map.r_netid) {
			goto nomem;
		}
	}

	if (orig->rpcb_map.r_addr) {
		new->rpcb_map.r_addr = strdup(orig->rpcb_map.r_addr);
		if (!new->rpcb_map.r_addr) {
			goto nomem;
		}
	}
	if (orig->rpcb_map.r_owner) {
		new->rpcb_map.r_owner = strdup(orig->rpcb_map.r_owner);
		if (!new->rpcb_map.r_owner) {
			goto nomem;
		}
	}
	new->rpcb_map.r_prog = orig->rpcb_map.r_prog;
	new->rpcb_map.r_vers = orig->rpcb_map.r_vers;

	*newp = new;
	return 0;

nomem:
	if (new->rpcb_map.r_netid) {
		free(new->rpcb_map.r_netid);
		new->rpcb_map.r_netid = NULL;
	}
	if (new->rpcb_map.r_addr) {
		free(new->rpcb_map.r_addr);
		new->rpcb_map.r_addr = NULL;
	}
	if (new->rpcb_map.r_owner) {
		free(new->rpcb_map.r_owner);
		new->rpcb_map.r_owner = NULL;
	}
	return ENOMEM;
}

int 
rpcbproc_copy_rpcb_list(rpcblist *orig, rpcblist **newp) 
{
	rpcblist *ent;
	rpcblist *tail;
	rpcblist *tmp;
	int err;

	tail = NULL;
	*newp = NULL;
	
	for (ent = orig; ent != NULL; ent = ent->rpcb_next) {
		err = rpcbproc_copy_rpcblistent(ent, &tmp);
		if (err != 0) {
			if (*newp != NULL) {
				axdr_free((axdrproc_t)
					  &axdr_rpcblist_ptr, newp);
			}
			return err;
		}
		if (tail) {
			tail->rpcb_next = tmp;
		} else {
			*newp = tmp;
		}
		tail = tmp;
		tmp->rpcb_next = NULL;
	}

	return 0;
}
