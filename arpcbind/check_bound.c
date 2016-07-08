/*	$NetBSD: check_bound.c,v 1.2 2000/06/22 08:09:26 fvdl Exp $	*/
/*	$FreeBSD: src/usr.sbin/rpcbind/check_bound.c,v 1.4 2002/10/07 02:56:59 alfred Exp $ */

/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
/*
 * Copyright (c) 1986 - 1991 by Sun Microsystems, Inc.
 */

/* #ident	"@(#)check_bound.c	1.15	93/07/05 SMI" */

#if 0
#ifndef lint
static	char sccsid[] = "@(#)check_bound.c 1.11 89/04/21 Copyr 1989 Sun Micro";
#endif
#endif

/*
 * check_bound.c
 * Checks to see whether the program is still bound to the
 * claimed address and returns the univeral merged address
 *
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <libarpc/arpc.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "rpcbind.h"

struct fdlist {
	int fd;
	ar_netid_t *nconf;
	struct fdlist *next;
	int check_binding;
};

static struct fdlist *fdhead;	/* Link list of the check fd's */
static struct fdlist *fdtail;
static char *nullstring = "";

static bool_t check_bound __P((struct fdlist *, const char *uaddr));

static int
ar_netid2fd(ar_netid_t *nid)
{
	int type;

	if (!nid) {
		return -1;
	}
	
	switch (nid->an_semantics) {
	case AR_SEM_CLTS:
		type = SOCK_DGRAM;
		break;
	case AR_SEM_COTS:
		type = SOCK_STREAM;
		break;
	default:
		return -1;
	}

	return socket(nid->an_family, type, nid->an_proto);
}


/*
 * Returns 1 if the given address is bound for the given addr & transport
 * For all error cases, we assume that the address is bound
 * Returns 0 for success.
 */
static bool_t
check_bound(struct fdlist *fdl, const char *uaddr)
{
	arpc_addr_t *na;
	int fd;
	int ans;
	int err;

	if (fdl->check_binding == FALSE) {
		return (TRUE);
	}

	err = ar_uaddr2taddr_af(fdl->nconf->an_family, uaddr, &na);
	if (err != 0) {
		return (TRUE); /* punt, should never happen */
	}

	fd = ar_netid2fd(fdl->nconf);
	if (fd < 0) {
		free(na->buf);
		free(na);
		return (TRUE);
	}

	ans = bind(fd, (struct sockaddr *)na->buf, na->len);

	close(fd);
	free(na->buf);
	free(na);

	return (ans == 0 ? FALSE : TRUE);
}

int
add_bndlist(ar_netid_t *nid)
{
	struct fdlist *fdl;

	fdl = malloc(sizeof (struct fdlist));
	if (fdl == NULL) {
		syslog(LOG_ERR, "no memory!");
		return (-1);
	}
	fdl->nconf = nid;
	fdl->next = NULL;
	if (fdhead == NULL) {
		fdhead = fdl;
		fdtail = fdl;
	} else {
		fdtail->next = fdl;
		fdtail = fdl;
	}
	/* XXX no bound checking for now */
	fdl->check_binding = FALSE;

	return 0;
}

bool_t
is_bound(const char *netid, const char *uaddr)
{
	struct fdlist *fdl;

	for (fdl = fdhead; fdl; fdl = fdl->next) {
		if (strcmp(fdl->nconf->an_netid, netid) == 0) {
			break;
		}
	}
	if (fdl == NULL) {
		return (TRUE);
	}
	return (check_bound(fdl, uaddr));
}

/*
 * Returns NULL if there was some system error.
 * Returns "" if the address was not bound, i.e the server crashed.
 * Returns the merged address otherwise.
 */
char *
mergeaddr(ar_svc_xprt_t *xprt, const char *netid, const char *uaddr,
	  const char *saddr)
{
	struct fdlist *fdl;
	const char *c_uaddr;
	const char *s_uaddr;
	char *m_uaddr, *allocated_uaddr = NULL;
	arpc_addr_t *t_addr;
	int err;

	for (fdl = fdhead; fdl; fdl = fdl->next) {
		if (strcmp(fdl->nconf->an_netid, netid) == 0) {
			break;
		}
	}
	if (fdl == NULL) {
		return (NULL);
	}
	if (check_bound(fdl, uaddr) == FALSE)
		/* that server died */
		return (nullstring);
	/*
	 * If saddr is not NULL, the remote client may have included the
	 * address by which it contacted us.  Use that for the "client" uaddr,
	 * otherwise use the info from the ar_svc_xprt_t.
	 */
	if (saddr != NULL) {
		c_uaddr = saddr;
	} else {
		t_addr = ar_svc_getrpccaller(xprt);
		if (!t_addr) {
			syslog(LOG_ERR, "get caller failed");
			return (NULL);
		}
		err = ar_taddr2uaddr_af(fdl->nconf->an_family, t_addr,
					&allocated_uaddr);
		free(t_addr->buf);
		free(t_addr);
		t_addr = NULL;
		if (err != 0) {
			syslog(LOG_ERR, "taddr2uaddr failed for %s",
			       fdl->nconf->an_netid);
			return (NULL);
		}
		c_uaddr = allocated_uaddr;
	}

#ifdef ND_DEBUG
	if (debugging) {
		if (saddr == NULL) {
			fprintf(stderr, "mergeaddr: client uaddr = %s\n",
			    c_uaddr);
		} else {
			fprintf(stderr, "mergeaddr: contact uaddr = %s\n",
			    c_uaddr);
		}
	}
#endif
	s_uaddr = uaddr;
	/*
	 * This is all we should need for IP 4 and 6
	 */
	t_addr = ar_svc_getrpccaller(xprt);
	if (!t_addr) {
		if (allocated_uaddr != NULL) {
			free(allocated_uaddr);
		}
		syslog(LOG_ERR, "get caller failed");
		return (NULL);
	}

	m_uaddr = addrmerge(t_addr, s_uaddr, c_uaddr, netid);
	free(t_addr->buf);
	free(t_addr);
	t_addr = NULL;

#ifdef ND_DEBUG
	if (debugging) {
		fprintf(stderr, "mergeaddr: uaddr = %s, merged uaddr = %s\n",
				uaddr, m_uaddr);
	}
#endif
	if (allocated_uaddr != NULL) {
		free(allocated_uaddr);
	}
	return (m_uaddr);
}

/*
 * Returns a netconf structure from its internal list.  This
 * structure should not be freed.
 */
ar_netid_t *
rpcbind_get_conf(const char *netid)
{
	struct fdlist *fdl;

	for (fdl = fdhead; fdl; fdl = fdl->next) {
		if (strcmp(fdl->nconf->an_netid, netid) == 0) {
			break;
		}
	}
	if (fdl == NULL) {
		return (NULL);
	}
	return (fdl->nconf);
}
