/*
 * $NetBSD: rpcb_stat.c,v 1.2 2000/07/04 20:27:40 matt Exp $
 * $FreeBSD: src/usr.sbin/rpcbind/rpcb_stat.c,v 1.4 2003/10/29 09:29:23 mbr Exp $
 */
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
/* #pragma ident   "@(#)rpcb_stat.c 1.7     94/04/25 SMI" */

/*
 * rpcb_stat.c
 * Allows for gathering of statistics
 *
 * Copyright (c) 1990 by Sun Microsystems, Inc.
 */

#include <stdio.h>
#include <libarpc/arpc.h>
#include "rpcb_prot.h"
#include "pmap_prot.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include "rpcbind.h"

static rpcb_stat_byvers inf;

void
rpcbs_init()
{

}

void
rpcbs_procinfo(arpcvers_t rtype, arpcproc_t proc)
{
	switch (rtype + 2) {
#ifdef PORTMAP
	case PMAPVERS:		/* version 2 */
		if (proc > rpcb_highproc_2)
			return;
		break;
#endif
	case RPCBVERS:		/* version 3 */
		if (proc > rpcb_highproc_3)
			return;
		break;
	case RPCBVERS4:		/* version 4 */
		if (proc > rpcb_highproc_4)
			return;
		break;
	default: return;
	}
	inf[rtype].info[proc]++;
	return;
}

void
rpcbs_set(arpcvers_t rtype, bool_t success)
{
	if ((rtype >= RPCBVERS_STAT) || (success == FALSE))
		return;
	inf[rtype].setinfo++;
	return;
}

void
rpcbs_unset(arpcvers_t rtype, bool_t success)
{
	if ((rtype >= RPCBVERS_STAT) || (success == FALSE))
		return;
	inf[rtype].unsetinfo++;
	return;
}

void
rpcbs_getaddr(arpcvers_t rtype, arpcprog_t prog, arpcvers_t vers,
	      const char *netid, const char *uaddr)
{
	rpcbs_addrlist *al;
	ar_netid_t *nconf;

	if (rtype >= RPCBVERS_STAT) {
		return;
	}
	for (al = inf[rtype].addrinfo; al; al = al->next) {

		if(al->netid == NULL) {
			return;
		}
		if ((al->prog == prog) && (al->vers == vers) &&
		    (strcmp(al->netid, netid) == 0)) {
			if ((uaddr == NULL) || (uaddr[0] == 0)) {
				al->failure++;
			} else {
				al->success++;
			}
			return;
		}
	}
	nconf = rpcbind_get_conf(netid);
	if (nconf == NULL) {
		return;
	}
	al = (rpcbs_addrlist *) malloc(sizeof (rpcbs_addrlist));
	if (al == NULL) {
		return;
	}
	al->prog = prog;
	al->vers = vers;
	al->netid = (char *)nconf->an_netid;
	if ((uaddr == NULL) || (uaddr[0] == 0)) {
		al->failure = 1;
		al->success = 0;
	} else {
		al->failure = 0;
		al->success = 1;
	}
	al->next = inf[rtype].addrinfo;
	inf[rtype].addrinfo = al;
}

void
rpcbs_rmtcall(arpcvers_t rtype, arpcproc_t rpcbproc, arpcprog_t prog,
	      arpcvers_t vers, arpcproc_t proc, const char *netid,
	      rpcblist_ptr rbl)
{
	rpcbs_rmtcalllist *rl;
	ar_netid_t *nconf;

	if (rtype > RPCBVERS_STAT) {
		return;
	}
	for (rl = inf[rtype].rmtinfo; rl; rl = rl->next) {

		if(rl->netid == NULL) {
			return;
		}

		if ((rl->prog == prog) && (rl->vers == vers) &&
		    (rl->proc == proc) &&
		    (strcmp(rl->netid, netid) == 0)) {
			if ((rbl == NULL) ||
			    (rbl->rpcb_map.r_vers != vers)) {
				rl->failure++;
			} else {
				rl->success++;
			}
			if (rpcbproc == RPCBPROC_INDIRECT) {
				rl->indirect++;
			}
			return;
		}
	}
	nconf = rpcbind_get_conf(netid);
	if (nconf == NULL) {
		return;
	}
	rl = (rpcbs_rmtcalllist *) malloc(sizeof (rpcbs_rmtcalllist));
	if (rl == NULL) {
		return;
	}
	rl->prog = prog;
	rl->vers = vers;
	rl->proc = proc;
	rl->netid = (char *)nconf->an_netid;
	if ((rbl == NULL) ||
		    (rbl->rpcb_map.r_vers != vers)) {
		rl->failure = 1;
		rl->success = 0;
	} else {
		rl->failure = 0;
		rl->success = 1;
	}
	rl->indirect = 1;
	rl->next = inf[rtype].rmtinfo;
	inf[rtype].rmtinfo = rl;
	return;
}

bool_t
rpcbproc_getstat(void *argp, rpcb_stat_byvers *result,
		 ar_svc_req_t *rqstp, arpcvers_t vers)
{
	memcpy(result, &inf, sizeof(inf));
	return TRUE;
}
