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
 * Copyright (c) 1986-1991 by Sun Microsystems Inc. 
 */

/*
 * rpcb_clnt.c
 * interface to rpcbind rpc service.
 *
 * Copyright (C) 1988, Sun Microsystems, Inc.
 */

#include "compat.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/poll.h>
#include <assert.h>
#include <libarpc/arpc.h>
#include "rpcb_prot.h"
#include "pmap_prot.h"
#include <netinet/in.h>		/* FOR IPPROTO_TCP/UDP definitions */
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <syslog.h>

#include "rpc_com.h"

#define TOTTIMEOUT 	{ 60, 0}
#define BINDTIMEOUT 	{ 15, 0}
#define RETTIMEOUT 	{ 3, 0}

#define	CLCR_GET_RPCB_TIMEOUT	1
#define	CLCR_SET_RPCB_TIMEOUT	2

typedef enum rpcb_state_e {
	RPCB_STATE_RESOLVE,
	RPCB_STATE_GETADDRLIST,
	RPCB_STATE_GETADDR,
} rpcb_state_t;

typedef enum rpcb_op_e {
	RPCB_OP_GETADDR,
	RPCB_OP_CLNT_CREATE,
} rpcb_op_t;

struct arpcb_client_s {
	ar_client_t		*rbs_client;
	rpcb_state_t		rbs_state;
	rpcb_op_t		rbs_op;
	ar_ioctx_t 		rbs_ioctx;
	RPCB			rbs_parms;
	char			*rbs_host;
	arpc_addr_t		rbs_addr;	/* should be list */
	struct timespec		rbs_time_limit;
	struct timespec		rbs_call_timeout;
	const char		*rbs_active_netid;
	const char		*rbs_original_netid;
	ar_clnt_call_obj_t	rbs_call_obj;
	int			rbs_vers;
	union {
		arpcb_findaddr_fn_t	rbs_find_cb;
		arpcb_clnt_fn_t		rbs_clnt_cb;
	}			rbs_fn;
	void			*rbs_arg;
};


static int got_entry(ar_ioctx_t, rpcb_entry_list_ptr, const char *netid, 
		     arpc_addr_t **retp);

static int rpcb_io_base_create(ar_ioctx_t ioctx, const char *netid,
			       const char *host, const struct timespec *tmout, 
			       rpcb_op_t op, arpc_createerr_t *errp, 
			       arpcb_client_t *retp);
/*
 * Set a mapping between program, version and address.
 * Calls the rpcbind service to do the mapping.
 */
bool_t
arpcb_set(arpcprog_t program, arpcvers_t version, const char *netid, 
	  const arpc_addr_t *address)
{
	return FALSE;
}


/*
 * Remove the mapping between program, version and netbuf address.
 * Calls the rpcbind service to do the un-mapping.
 * If netbuf is NULL, unset for all the transports, otherwise unset
 * only for the given transport.
 */
bool_t
arpcb_unset(arpcprog_t program, arpcvers_t version, const char *netid)
{
	return FALSE;
}


/*
 * From the merged list, find the appropriate entry
 */
static int
got_entry(ar_ioctx_t ioctx, rpcb_entry_list_ptr relp, const char *netid,
	  arpc_addr_t **retp)
{
	arpc_addr_t *na = NULL;
	rpcb_entry_list_ptr sp;
	rpcb_entry *rmap;
	ar_netid_t *info;
	int err;

	if (!relp || !netid || !retp) {
		return EINVAL;
	}

	err = ar_str2netid(ioctx, netid, &info);
	if (err != EOK) {
		return err;
	}
	if (!info->an_protoname) {
		return ENOENT;
	}
	
	for (sp = relp; sp != NULL; sp = sp->rpcb_entry_next) {
		rmap = &sp->rpcb_entry_map;
		if ((strcmp(info->an_protoname, rmap->r_nc_proto) != 0) ||
		    (strcmp(info->an_familyname, rmap->r_nc_protofmly) != 0) ||
		    (strcmp(netid, rmap->r_nc_netid) != 0) ||
		    (info->an_semantics != rmap->r_nc_semantics) ||
		    (rmap->r_maddr == NULL) || (rmap->r_maddr[0] == 0)) {
			continue;
		}
		err = ar_uaddr2taddr_af(info->an_family, rmap->r_maddr, &na);
		if (err != EOK) {
			return err;
		}
#ifdef ND_DEBUG
		fprintf(stderr, "\tRemote address is [%s].\n",
			rmap->r_maddr);
		if (!na) {
			fprintf(stderr,
				"\tCouldn't resolve remote address!\n");
		}
#endif
		break;
	}
	*retp = na;
	return EOK;
}

/*
 * Quick check to see if rpcbind is up.  Tries to connect over
 * local transport.
 */
bool_t
__rpcbind_is_up()
{
	return TRUE;
}


static void
rpcb_getaddr_done(ar_clnt_call_obj_t cco, void *arg, 
		  const arpc_err_t *errp, void *result)
{
	RPCB			*parms;
	arpcb_client_t 		rpcb;
	arpc_createerr_t	cferr;
	arpc_addr_t		*address;
	arpc_addr_t		servaddr;
	ar_client_t		*clnt;
	char			**uap;
	rpcb_entry_list_ptr	*relp;
	char			*ua;
	rpcb_entry_list_ptr	rel;
	ar_ioctx_t		ioctx;
	bool_t			notdone;
	struct timespec 	cur;
	struct timespec 	diff;
	struct timespec		zero;
	int			err;

	notdone = FALSE;
	address = NULL;
	ua = NULL;
	relp = NULL;
	rpcb = (arpcb_client_t)arg;
	assert(rpcb != NULL);
	assert(cco == rpcb->rbs_call_obj);
	rpcb->rbs_call_obj = NULL;	/* remove ptr, it's done */

	parms = &rpcb->rbs_parms;
	clnt = rpcb->rbs_client;
	rpcb->rbs_call_obj = NULL;
	memset(&cferr, 0, sizeof(cferr));
	cferr.cf_stat = ARPC_SUCCESS;

	if (rpcb->rbs_state == RPCB_STATE_GETADDRLIST) {
		relp = (rpcb_entry_list_ptr *)result;
		uap = &ua;
		ua = NULL;
	} else {
		uap = (char **)result;
		relp = &rel;
		rel = NULL;
	}

	ioctx = cco->cco_client->cl_ioctx;

	if (errp->re_status == ARPC_SUCCESS) {
		if (rpcb->rbs_state == RPCB_STATE_GETADDRLIST) {
			relp = (rpcb_entry_list_ptr *)result;
			err = got_entry(ioctx, *relp,
					rpcb->rbs_original_netid, &address);
			if (err != EOK) {
				address = NULL;
			}
		} else {
			if ((*uap == NULL) || ((*uap)[0] == 0)) {
				/* address unknown */
				cferr.cf_stat = ARPC_PROGNOTREGISTERED;
				goto done;
			}
			err = ar_uaddr2taddr(ioctx, rpcb->rbs_active_netid, 
					     *uap, &address);
			if (err != EOK) {
				address = NULL;
			}
			
#ifdef ND_DEBUG
			fprintf(stderr, "\tRemote address is [%s]\n", *uap);
			if (!address) {
				fprintf(stderr, "\tCouldn't resolve "
					"remote address!\n");
			}
#endif
			if (!address) {
				/* We don't know about your universal 
				 * address 
				 */
				cferr.cf_stat = ARPC_N2AXLATEFAILURE;
				goto done;
			}
		}
		if (address && address->len > 0) {
			/* success.  Add the address to the port info. */
			ar_clnt_control(clnt, AR_CLGET_SVC_ADDR, 
					(char *)&servaddr);
			ar_fixup_addr(address, &servaddr);
			goto done;
		}
	} else if (errp->re_status == ARPC_PROGVERSMISMATCH) {
		if (errp->re_vers.low > RPCBVERS4) {
			cferr.cf_error = *errp;
			cferr.cf_stat = errp->re_status;
			goto done;  /* a new version, can't handle */
		}
	} else if (errp->re_status != ARPC_PROGUNAVAIL) {
		/* Cant handle this error */
		cferr.cf_error = *errp;
		cferr.cf_stat = errp->re_status;
		goto done;
	}

	if (rpcb->rbs_state != RPCB_STATE_GETADDRLIST) {
		rpcb->rbs_vers--;
	}

	/* update state */
	rpcb->rbs_state = RPCB_STATE_GETADDR;
	if (rpcb->rbs_vers <= RPCBVERS) {
		cferr.cf_stat = ARPC_PROGNOTREGISTERED;
		ar_clnt_call_geterr(cco, &cferr.cf_error);
		goto done;
	}

	/* check for timeout */
	ar_gettime(&cur);
	tspecsub(&rpcb->rbs_time_limit, &cur, &diff);
	tspecclear(&zero);
	if (tspeccmp(&diff, &zero, <=)) {
		/* time expired already */
		cferr.cf_stat = ARPC_TIMEDOUT;
		goto done;
	}

	/* kick off next round of commands... */
	ar_clnt_control(clnt, AR_CLSET_VERS, (char *)&rpcb->rbs_vers);
	err = ar_clnt_call_async_inplace(clnt, (arpcproc_t)RPCBPROC_GETADDR,
					 (axdrproc_t)axdr_rpcb, (char *)parms,
					 (axdrproc_t)axdr_wrapstring,
					 sizeof(char *), rpcb_getaddr_done, 
					 rpcb, &rpcb->rbs_call_timeout,
					 &rpcb->rbs_call_obj);
	if (err != 0) {
		rpcb->rbs_call_obj = NULL;
		cferr.cf_stat = ARPC_SYSTEMERROR;
		cferr.cf_error.re_errno = err;
		goto done;
	}

	/* need to free up local state, because we're scheduled to
	 * call again. so we're...
	 */
	notdone = TRUE;

 done:
	if (notdone) {
		if (address) {
			if (address->buf) {
				free(address->buf);
			}
			free(address);
		}
		return;
	}

	(*rpcb->rbs_fn.rbs_find_cb)(rpcb, rpcb->rbs_arg, &cferr, address);

	if (address) {
		if (address->buf) {
			free(address->buf);
		}
		free(address);
		address = NULL;
	}

	arpcb_clnt_destroy(rpcb);
}


/**
 * Callback function that runs after the host has been resolved to 
 * an address in the active_nconf domain and put in rbs_addr.
 *
 * @param rpcb
 */
static void
rpcb_resolve_done(arpcb_client_t rpcb)
{
	arpc_createerr_t cferr;
	struct timespec cur;
	struct timespec diff;
	struct timespec div;
	struct timespec zero;
	ar_clnt_attr_t attr;
	ar_netid_t *cur_info;
	ar_netid_t *orig_info;
	axdrproc_t xdrp1;
	int len1;
	arpcproc_t proc;
	double val;
	ar_client_t *clnt;
	RPCB *parms;
	int calls;
	int count;
	int err;

	if (!rpcb) {
		return;
	}

	memset(&cferr, 0, sizeof(cferr));
	cferr.cf_stat = ARPC_SUCCESS;

	ar_gettime(&cur);
	tspecsub(&rpcb->rbs_time_limit, &cur, &diff);
	tspecclear(&zero);
	if (tspeccmp(&diff, &zero, <=)) {
		/* time expired already */
		cferr.cf_stat = ARPC_TIMEDOUT;
		goto error;
	}

	err = ar_clnt_attr_init(&attr);
	if (err != 0) {
		cferr.cf_stat = ARPC_SYSTEMERROR;
		cferr.cf_error.re_errno = err;
		goto error;
	}
	/* create the client to make our request */
	err = ar_clnt_tli_create(rpcb->rbs_ioctx, rpcb->rbs_active_netid,
				 &rpcb->rbs_addr, (arpcprog_t)RPCBPROG,
				 (arpcvers_t)RPCBVERS4, &attr, &cferr, &clnt);
	ar_clnt_attr_destroy(&attr);
	if (err != 0) {
		if (cferr.cf_stat == ARPC_SUCCESS) {
			cferr.cf_stat = ARPC_ERRNO;
			cferr.cf_error.re_errno = err;
		}
		goto error;
	}

	if (rpcb->rbs_op == RPCB_OP_CLNT_CREATE) {
		/* we've completed what we wanted */
		(*rpcb->rbs_fn.rbs_clnt_cb)(rpcb, rpcb->rbs_arg, &cferr, clnt);
		arpcb_clnt_destroy(rpcb);
		return;
	}

	/* continue on with getaddr operation */
	rpcb->rbs_client = clnt;

	err  = ar_str2netid(rpcb->rbs_ioctx, rpcb->rbs_original_netid,
			    &orig_info);
	err |= ar_str2netid(rpcb->rbs_ioctx, rpcb->rbs_active_netid, 
			    &cur_info);
	if (err != EOK) {
		cferr.cf_stat = ARPC_UNKNOWNPROTO;
		goto error;
	}

	if (orig_info->an_semantics == AR_SEM_COTS && 
	    orig_info->an_semantics != cur_info->an_semantics && 
	    strcmp(rpcb->rbs_original_netid, "local") != 0) {
		rpcb->rbs_state = RPCB_STATE_GETADDRLIST;
	} else {
		rpcb->rbs_state = RPCB_STATE_GETADDR;
	}

	parms = &rpcb->rbs_parms;

	/*
	 * Now we try version 4 and then 3.
	 * We also send the remote system the address we used to
	 * contact it in case it can help to connect back with us
	 */
	err = ar_taddr2uaddr_af(cur_info->an_family,
				&rpcb->rbs_addr, &parms->r_addr);
	if (err != EOK) {
		cferr.cf_stat = ARPC_SYSTEMERROR;
		cferr.cf_error.re_errno = err;
		goto error;
	}

	/* configure the timeout based on the number of retries and the
	 * number of operations we need to do.
	 */
	ar_clnt_control(clnt, AR_CLGET_RETRY_COUNT, (char *)&count);

	/*
	 * multiply by the number of possible rpc's we'll do.
	 */
	calls = RPCBVERS4 - RPCBVERS + 1;
	if (rpcb->rbs_state == RPCB_STATE_GETADDRLIST) {
		calls++;
	}
	count *= calls;

	/* divide time remaining to determine timeout for individual calls. */
	div.tv_sec = diff.tv_sec / count;
	val = (double)(diff.tv_sec % count);
	val /= (double)count;
	div.tv_nsec = (int)(val * 1000000000.0) + diff.tv_nsec / count;
	tspecadd(&div, &zero, &div);
	
	if (tspeccmp(&div, &zero, <=)) {
		/* time expired already */
		cferr.cf_stat = ARPC_TIMEDOUT;
		goto error;
	}

	/* setup the partial timeout value */
	ar_clnt_control(clnt, AR_CLSET_RETRY_TIMEOUT_SPEC, (char *)&div);

	/* compute a timeout for the individual rpc calls */
	calls = RPCBVERS4 - RPCBVERS + 1;
	if (rpcb->rbs_state == RPCB_STATE_GETADDRLIST) {
		calls++;
	}
	div.tv_sec = diff.tv_sec / calls;
	val = (double)(diff.tv_sec % calls);
	val /= (double)calls;
	div.tv_nsec = (int)(val * 1000000000.0) + diff.tv_nsec / calls;
	tspecadd(&div, &zero, &div);
	rpcb->rbs_call_timeout = div;

	if (rpcb->rbs_state == RPCB_STATE_GETADDRLIST) {
		proc = (arpcproc_t)RPCBPROC_GETADDRLIST;
		xdrp1 = (axdrproc_t)axdr_rpcb_entry_list_ptr;
		len1 = sizeof(rpcb_entry_list_ptr);
	} else {
		proc = (arpcproc_t)RPCBPROC_GETADDR;
		xdrp1 = (axdrproc_t)axdr_wrapstring;
		len1 = sizeof(char *);
	}
	err = ar_clnt_call_async_inplace(clnt, proc, (axdrproc_t)axdr_rpcb, 
					 (char *)(void *)parms, xdrp1, len1,
					 rpcb_getaddr_done, rpcb, 
					 &rpcb->rbs_call_timeout,
					 &rpcb->rbs_call_obj);
	if (err == 0) {
		return;
	}
	cferr.cf_stat = ARPC_SYSTEMERROR;
	cferr.cf_error.re_errno = err;

 error:
	switch (rpcb->rbs_op) {
	case RPCB_OP_GETADDR:
		(*rpcb->rbs_fn.rbs_find_cb)(rpcb, rpcb->rbs_arg, &cferr, NULL);
		break;
	case RPCB_OP_CLNT_CREATE:
		(*rpcb->rbs_fn.rbs_clnt_cb)(rpcb, rpcb->rbs_arg, &cferr, NULL);
		break;
	}

	arpcb_clnt_destroy(rpcb);
}


static int
rpcb_resolve_addr(arpcb_client_t rpcb, arpc_createerr_t *errp)
{
	struct addrinfo hints, *res, *tres;
	arpc_addr_t taddr;
	ar_netid_t *info;
	int err;

	err = ar_str2netid(rpcb->rbs_ioctx, rpcb->rbs_active_netid, &info);
	if (err != EOK) {
		return err;
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = info->an_family;
	switch (info->an_semantics) {
	case AR_SEM_COTS:
		hints.ai_socktype = SOCK_STREAM;
		break;
	case AR_SEM_CLTS:
		hints.ai_socktype = SOCK_DGRAM;
		break;
	default:
		err = EINVAL;
		goto error;
	}
	hints.ai_protocol = 0;

#ifdef CLNT_DEBUG
	printf("trying netid %s family %d proto %d socktype %d\n",
	       rpcb->rbs_active_nconf.nc_netid, si.si_af, si.si_proto, 
	       si.si_socktype);
#endif
	/* FIXME: this is not an async resolve yet.... */
	/* not async, not multi-thread, not SAFE!!!! */
	if (getaddrinfo(rpcb->rbs_host, "sunrpc", &hints, &res) != 0) {
		err = EHOSTUNREACH;
		goto error;
	}

	for (tres = res; tres != NULL; tres = tres->ai_next) {
		taddr.buf = (char *)tres->ai_addr;
		taddr.len = taddr.maxlen = tres->ai_addrlen;
		/* FIXME: We used to do create as part of the resolve loop, so 
		 * we would try multiple addresses returned from the 
		 * lookup.  We don't do that anymore.  On connectionless
		 * transports, this would probably only ever lock onto the
		 * first address returned.  On conection oriented sockets,
		 * however, this would use multiple addreses. We may
		 * want to make the addr netbuf in the arpcb_client_t
		 * structure a list so the state machine can try making
		 * clients on all the addresses...
		 */
		if (rpcb->rbs_addr.buf) {
			free(rpcb->rbs_addr.buf);
			rpcb->rbs_addr.buf = NULL;
		}

		rpcb->rbs_addr.buf = malloc(taddr.maxlen);
		if (!rpcb->rbs_addr.buf) {
			break;
		}
		memcpy(rpcb->rbs_addr.buf, taddr.buf, taddr.maxlen);
		rpcb->rbs_addr.maxlen = taddr.maxlen;
		rpcb->rbs_addr.len = taddr.len;

		freeaddrinfo(res);

		rpcb_resolve_done(rpcb);
		return 0;
	}
	if (res) {
		freeaddrinfo(res);
	}

	err = EHOSTUNREACH;
error:
	if (errp) {
		ar_errno2err(&errp->cf_error, err);
		errp->cf_stat = errp->cf_error.re_status;
	}
	return err;
}


static int 
rpcb_io_base_create(ar_ioctx_t ioctx, const char *netid, 
		    const char *host, const struct timespec *tmout, 
		    rpcb_op_t op, arpc_createerr_t *errp, 
		    arpcb_client_t *retp)
{
	struct timespec start;
	const char *tnetid;
	arpcb_client_t rpcb;
	ar_netid_t *info;
	int err;
    
	if (!ioctx || !netid || !host || !tmout || !retp) {
		err = EINVAL;
		goto error;
	}

	rpcb = malloc(sizeof(*rpcb));
	if (!rpcb) {
		err = ENOMEM;
		goto error;
	}
	memset(rpcb, 0, sizeof(*rpcb));

	ar_gettime(&start);
	tspecadd(tmout, &start, &start);

	rpcb->rbs_ioctx = ioctx;
	rpcb->rbs_time_limit = start;
	rpcb->rbs_host = strdup(host);
	if (!rpcb->rbs_host) {
		arpcb_clnt_destroy(rpcb);
		err = ENOMEM;
		goto error;
	}

	rpcb->rbs_active_netid = strdup(netid);
	rpcb->rbs_original_netid = strdup(netid);
	if (!rpcb->rbs_active_netid || !rpcb->rbs_original_netid) {
		arpcb_clnt_destroy(rpcb);
		err = ENOMEM;
		goto error;
	}

	err = ar_str2netid(ioctx, netid, &info);
	if (err != EOK) {
		arpcb_clnt_destroy(rpcb);
		goto error;
	}

	/*
	 * If a COTS transport is being used, try getting address via CLTS
	 * transport.  This works only with version 4.
	 * NOTE: This is being done for all transports EXCEPT LOOPBACK
	 * because with loopback the cost to go to a COTS is same as
	 * the cost to go through CLTS, plus you get the advantage of
	 * finding out immediately if the local rpcbind process is dead.
	 * 
	 * In more concrete terms: we always use UDP to resolve the port,
	 * but we may want to use TCP for the link.  Because the rpcbind
	 * program bases the address & port response for GETADDR based on
	 * what link the request was received on, we use GETADDRLIST
	 * in this case so that we get all the available transports and 
	 * we can pick out the best one.
	 */
	if (info->an_semantics == AR_SEM_COTS && 
	    strcmp(netid, "local") != 0) {
		err = ar_class2netidstr(ioctx, AR_SEM_CLTS, info->an_family,
					&tnetid);
		if (err == EOK) {
			free((char *)rpcb->rbs_active_netid);
			rpcb->rbs_active_netid = strdup(tnetid);
			if (!rpcb->rbs_active_netid) {
				arpcb_clnt_destroy(rpcb);
				err = ENOMEM;
				goto error;
			}
		}
	}				
			
	rpcb->rbs_state = RPCB_STATE_RESOLVE;
	rpcb->rbs_vers = RPCBVERS4;
	rpcb->rbs_op = op;

	*retp = rpcb;
	return 0;

error:
	if (errp) {
		ar_errno2err(&errp->cf_error, err);
		errp->cf_stat = errp->cf_error.re_status;
	}
	return err;
}


int
arpcb_findaddr_create(ar_ioctx_t ioctx, const arpcprog_t program, 
		      const arpcvers_t version, const char *netid,
		      const char *host, arpcb_findaddr_fn_t fn, void *arg,
		      const struct timespec *tmout, arpc_createerr_t *errp, 
		      arpcb_client_t *retp)
{
	arpcb_client_t rpcb;
	RPCB *parms;
	int err;

	if (!ioctx || !netid || !host || !fn || !tmout || !retp) {
		return EINVAL;
	}

	err = rpcb_io_base_create(ioctx, netid, host, tmout, RPCB_OP_GETADDR,
				  errp, &rpcb);
	if (err != 0) {
		return err;
	}

	parms = &rpcb->rbs_parms;
	parms->r_prog = program;
	parms->r_vers = version;
	parms->r_netid = (char *)rpcb->rbs_active_netid;
	parms->r_owner = "";

	rpcb->rbs_arg = arg;
	rpcb->rbs_fn.rbs_find_cb = fn;

	/* set this up before we call the method, in case we get an immediate
	 * result...
	 */
	*retp = rpcb;

	err = rpcb_resolve_addr(rpcb, errp);
	if (err != 0) {
		arpcb_clnt_destroy(rpcb);
		*retp = NULL;
		return err;
	}

	return 0;
}


int
arpcb_clnt_create(ar_ioctx_t ioctx, const char *netid, 
		  const char *host, arpcb_clnt_fn_t fn, void *arg,
		  const struct timespec *tmout, arpc_createerr_t *errp,
		  arpcb_client_t *retp)
{
	arpcb_client_t rpcb;
	int err;

	if (!ioctx || !netid || !host || !fn || !tmout || !retp) {
		return EINVAL;
	}

	err = rpcb_io_base_create(ioctx, netid, host, tmout,
				  RPCB_OP_CLNT_CREATE, errp, &rpcb);
	if (err != 0) {
		return err;
	}

	rpcb->rbs_arg = arg;
	rpcb->rbs_fn.rbs_clnt_cb = fn;

	/* set this up before we call the method, in case we get an immediate
	 * result...
	 */
	*retp = rpcb;

	err = rpcb_resolve_addr(rpcb, errp);
	if (err != 0) {
		arpcb_clnt_destroy(rpcb);
		*retp = NULL;
		return err;
	}

	return 0;
}

    
void
arpcb_clnt_destroy(arpcb_client_t rpcb) 
{
	RPCB *parms;

	if (!rpcb) {
		return;
	}
	parms = &rpcb->rbs_parms;

	if (rpcb->rbs_active_netid) {
		free((char *)rpcb->rbs_active_netid);
		rpcb->rbs_active_netid = NULL;
	}
	if (rpcb->rbs_original_netid) {
		free((char *)rpcb->rbs_original_netid);
		rpcb->rbs_original_netid = NULL;
	}
	if (rpcb->rbs_host) {
		free(rpcb->rbs_host);
	}
	if (parms->r_addr) {
		free(parms->r_addr);
	}
	parms->r_addr = NULL;

	if (rpcb->rbs_call_obj) {
		ar_clnt_call_cancel(rpcb->rbs_call_obj);
	}
	rpcb->rbs_call_obj = NULL;

	if (rpcb->rbs_client) {
		ar_clnt_destroy(rpcb->rbs_client);
	}
	rpcb->rbs_client = NULL;

	if (rpcb->rbs_addr.buf) {
		free(rpcb->rbs_addr.buf);
		rpcb->rbs_addr.buf = NULL;
	}
	free(rpcb);
}

/* synchronous clnt create internal function */

struct getclnthandle_s {
	ar_client_t		**clntp;
	arpc_createerr_t	cerr;
	bool_t			done;
	int			err;
};

static void
getclnthandle_cb(arpcb_client_t rpcb, void *arg, arpc_createerr_t *errp,
		 ar_client_t *clnt)
{
	struct getclnthandle_s *done;

	done = (struct getclnthandle_s *)arg;
	done->done = TRUE;
	(*done->clntp) = clnt;
	done->cerr = *errp;
	if (errp->cf_stat == ARPC_TIMEDOUT) {
		done->err = ETIMEDOUT;
	} else if (errp->cf_stat != ARPC_SUCCESS) {
		done->err = EPROTO;
	} else {
		done->err = 0;
	}
}

static ar_client_t *
getclnthandle(ar_ioctx_t ioctx, const char *host, const char *netid, 
	      const struct timespec *tout, arpc_createerr_t *errp)
{
	struct getclnthandle_s done;
	arpcb_client_t rpcb;
	ar_client_t *clnt;
	int err;

	clnt = NULL;
	done.clntp = &clnt;
	done.done = FALSE;
	done.err = 0;
	done.cerr.cf_stat = ARPC_SUCCESS;
	done.cerr.cf_error.re_status = ARPC_SUCCESS;

	err = arpcb_clnt_create(ioctx, netid, host, getclnthandle_cb,
				&done, tout, errp, &rpcb);
	if (err != 0) {
		return NULL;
	}
	
	while (!done.done) {
		err = ar_ioctx_loop(ioctx);
		if (err != 0) {
			if (err == EINTR) {
				continue;
			}
			arpcb_clnt_destroy(rpcb);
			break;
		}
	}
			
	if (done.err != 0) {
		clnt = NULL;
	}

	if (errp) {
		if (done.cerr.cf_stat == ARPC_SUCCESS) {
			ar_errno2err(&errp->cf_error, done.err);
			errp->cf_stat = errp->cf_error.re_status;
		} else {
			*errp = done.cerr;
		}
	}

	return clnt;
}


/*
 * Get a copy of the current maps.
 * Calls the rpcbind service remotely to get the maps.
 *
 * It returns only a list of the services
 * It returns NULL on failure.
 */
struct rpcblist *
arpcb_getmaps(ar_ioctx_t ioctx, const char *netid, 
	      const char *host, arpc_createerr_t *errp)
{
	struct timespec tspec = TOTTIMEOUT;
	struct timespec btmout = BINDTIMEOUT;
	struct rpcblist *head = NULL;
	ar_client_t *client;
	ar_stat_t clnt_st;
	arpcvers_t vers = 0;
	arpc_err_t err;

	if (errp) {
		errp->cf_stat = ARPC_SUCCESS;
		errp->cf_error.re_status = ARPC_SUCCESS;
	}

	client = getclnthandle(ioctx, host, netid, &btmout, errp);
	if (client == NULL) {
		return (head);
	}

	clnt_st = ar_clnt_call(client, (arpcproc_t)RPCBPROC_DUMP,
			       (axdrproc_t)axdr_void, NULL, 
			       (axdrproc_t)axdr_rpcblist_ptr,
			       (char *)(void *)&head, sizeof(head), &tspec,
			       &err);
	if (clnt_st == ARPC_SUCCESS) {
		goto done;
	}

	if ((clnt_st != ARPC_PROGVERSMISMATCH) &&
	    (clnt_st != ARPC_PROGUNAVAIL)) {
		errp->cf_error = err;
		errp->cf_stat = err.re_status;
		goto done;
	}

	/* fall back to earlier version */
	ar_clnt_control(client, AR_CLGET_VERS, (char *)(void *)&vers);
	if (vers == RPCBVERS4) {
		vers = RPCBVERS;
		ar_clnt_control(client, AR_CLSET_VERS, (char *)(void *)&vers);
		if (ar_clnt_call(client, (arpcproc_t)RPCBPROC_DUMP,
				 (axdrproc_t)axdr_void, NULL,
				 (axdrproc_t)axdr_rpcblist_ptr,
				 (char *)(void *)&head,
				 sizeof(head), &tspec, &err) == ARPC_SUCCESS) {
			goto done;
		}
		errp->cf_error = err;
		errp->cf_stat = err.re_status;
	}

done:
	ar_clnt_destroy(client);
	return (head);
}

/*
 * rpcbinder remote-call-service interface.
 * This routine is used to call the rpcbind remote call service
 * which will look up a service program in the address maps, and then
 * remotely call that routine with the given parameters. This allows
 * programs to do a lookup and call in one step.
*/
ar_stat_t
arpcb_rmtcall(ar_ioctx_t ioctx, const char *netid, const char *host,
	      arpcprog_t prog, arpcvers_t vers, arpcproc_t proc,
	      axdrproc_t xdrargs, caddr_t argsp, axdrproc_t xdrres,
	      caddr_t resp, struct timeval tout, 
	      const arpc_addr_t *addr_ptr, arpc_createerr_t *errp)
{
	struct timespec tspec;
	struct timespec rettout = RETTIMEOUT;
	ar_client_t *client;
	ar_stat_t stat;
	struct r_rpcb_rmtcallargs a;
	struct r_rpcb_rmtcallres r;
	arpcvers_t rpcb_vers;
	ar_netid_t *info;
	arpc_createerr_t cerr;
	int err;

	tspec.tv_sec = tout.tv_sec;
	tspec.tv_nsec = tout.tv_usec * 1000;
	stat = ARPC_SUCCESS;

	err = ar_str2netid(ioctx, netid, &info);
	if (err != EOK) {
		stat = ARPC_UNKNOWNPROTO;
		if (errp) {
			errp->cf_stat = stat;
			errp->cf_error.re_status = stat;
		}
		return stat;
	}

	client = getclnthandle(ioctx, host, netid, &tspec, &cerr);
	if (client == NULL) {
		if (errp) {
			*errp = cerr;
		}
		return cerr.cf_stat;
	}

	/*LINTED const castaway*/
	ar_clnt_control(client, AR_CLSET_RETRY_TIMEOUT_SPEC, 
		     (char *)(void *)&rettout);
	a.prog = prog;
	a.vers = vers;
	a.proc = proc;
	a.args.args_val = argsp;
	a.xdr_args = xdrargs;
	r.addr = NULL;
	r.results.results_val = resp;
	r.xdr_res = xdrres;

	for (rpcb_vers = RPCBVERS4; rpcb_vers >= RPCBVERS; rpcb_vers--) {
		ar_clnt_control(client, AR_CLSET_VERS,
				(char *)(void *)&rpcb_vers);
		stat = ar_clnt_call(client, (arpcproc_t)RPCBPROC_CALLIT,
				    (axdrproc_t)axdr_rpcb_rmtcallargs, 
				    (char *)(void *)&a,
				    (axdrproc_t)axdr_rpcb_rmtcallres,
				    (char *)(void *)&r, sizeof(r), &tspec, 
				    &cerr.cf_error);
		if ((stat == ARPC_SUCCESS) && (addr_ptr != NULL)) {
			arpc_addr_t *na;
			/*LINTED const castaway*/
			err = ar_uaddr2taddr_af(info->an_family, r.addr, &na);
			if (err != EOK) {
				stat = ARPC_N2AXLATEFAILURE;
				/*LINTED const castaway*/
				((arpc_addr_t *)addr_ptr)->len = 0;
				goto error;
			}
			if (na->len > addr_ptr->maxlen) {
				/* Too long address */
				stat = ARPC_N2AXLATEFAILURE;
				free(na->buf);
				free(na);
				/*LINTED const castaway*/
				((arpc_addr_t *)addr_ptr)->len = 0;
				goto error;
			}
			memcpy(addr_ptr->buf, na->buf, (size_t)na->len);
			/*LINTED const castaway*/
			((arpc_addr_t *)addr_ptr)->len = na->len;
			free(na->buf);
			free(na);
			break;
		} else if ((stat != ARPC_PROGVERSMISMATCH) &&
			   (stat != ARPC_PROGUNAVAIL)) {
			errp->cf_stat = stat;
			goto cleanup;
		}
	}
	/* FALLTHROUGH */
error:
	if (errp) {
		errp->cf_stat = stat;
		errp->cf_error.re_status = stat;
	}		
cleanup:
	ar_clnt_destroy(client);
	if (r.addr) {
		axdr_free((axdrproc_t)axdr_wrapstring, 
			  (char *)(void *)&r.addr);
	}
	return (stat);
}
