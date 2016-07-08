/*
 * Copyright (C) 2010  Pace Plc
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Pace Plc nor the names of its
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
 * rpc_io.c
 *
 * event based io rpc layer.
 */

#include "compat.h"

#include <sys/param.h>
#include <sys/poll.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <libarpc/arpc.h>
#ifdef HAVE_LIBEVENT
#include <event.h>
#endif

#include "rpc_com.h"

int
ar_ioctx_create(ar_ioctx_t *ioctxp)
{
	ar_ioctx_t ret;

	if (!ioctxp) {
		return EINVAL;
	}

	ret = malloc(sizeof(struct ar_ioctx_s));
	if (!ret) {
		return ENOMEM;
	}
	memset(ret, 0, sizeof(struct ar_ioctx_s));
	TAILQ_INIT(&ret->icx_ep_list);
	TAILQ_INIT(&ret->icx_svc_list);
	TAILQ_INIT(&ret->icx_drv_list);

	*ioctxp = ret;
	return 0;
}

void
ar_ioctx_destroy(ar_ioctx_t ioctx)
{
	ar_ioep_t	ep;
	svc_callout_t	*cout;
	driver_map_t     drv;

	if (!ioctx) {
		return;
	}

	while ((ep = TAILQ_FIRST(&ioctx->icx_ep_list)) != NULL) {
		(*ep->iep_drv->epd_destroy)(ep);
	}

	while ((cout = TAILQ_FIRST(&ioctx->icx_svc_list)) != NULL) {
		TAILQ_REMOVE(&ioctx->icx_svc_list, cout, sc_listent);
		mem_free(cout, sizeof(*cout));
	}

	while ((drv = TAILQ_FIRST(&ioctx->icx_drv_list)) != NULL) {
		TAILQ_REMOVE(&ioctx->icx_drv_list, drv, drv_listent);
		mem_free(drv, sizeof(*drv));
	}

	free(ioctx);
}

int
ar_ioctx_add_vcd(ar_ioctx_t ioctx, ar_vcd_t vcd, const char *proto)
{
	driver_map_t drv;

	if (!ioctx || !vcd || !proto || proto[0] == '\0')
		return EINVAL;

	TAILQ_FOREACH(drv, &ioctx->icx_drv_list, drv_listent) {
		if (!strncmp(drv->drv_proto, proto,
			     sizeof(drv->drv_proto))) {
			return EEXIST;
		}
	}

	drv = malloc(sizeof(struct driver_map_s));
	if (!drv)
		return ENOMEM;
	strlcpy(drv->drv_proto, proto, sizeof(drv->drv_proto));
	drv->drv_vcd = vcd;
	TAILQ_INSERT_TAIL(&ioctx->icx_drv_list, drv, drv_listent);
	return EOK;
}

int
ar_ioctx_remove_vcd(ar_ioctx_t ioctx, const char *proto)
{
	driver_map_t drv;
	if (!ioctx || !proto || proto[0] == '\0')
		return EINVAL;

	TAILQ_FOREACH(drv, &ioctx->icx_drv_list, drv_listent) {
		if (!strncmp(drv->drv_proto, proto,
			     sizeof(drv->drv_proto))) {
			TAILQ_REMOVE(&ioctx->icx_drv_list, drv, drv_listent);
			mem_free(drv, sizeof(*drv));
			break;
		}
	}
	return EOK;
}

/* pfd specific interface should eventually become more generic */
int
ar_ioctx_pfd_count(ar_ioctx_t ioctx, int *countp)
{
	ar_ioep_t ioep;
	int count;

	if (!ioctx || !countp) {
		return EINVAL;
	}

	count = 1; /* include timer pfd */

	TAILQ_FOREACH(ioep, &ioctx->icx_ep_list, iep_listent) {
		count++;
	}
	*countp = count;
	return 0;
}


int
ar_ioctx_pfd_setup(ar_ioctx_t ioctx, struct pollfd *pfds,
		   int *countp, int *timeoutp)
{
	ar_ioep_t ep;
	int min_timeout = -1;
	int size;
	int timeout;
	int i;

	if (!ioctx || !pfds || !countp || !timeoutp) {
		return EINVAL;
	}

	size = *countp;
	i = 0;

	TAILQ_FOREACH(ep, &ioctx->icx_ep_list, iep_listent) {
		if (i >= size) {
			return EINVAL;
		}
		(*ep->iep_drv->epd_poll_setup)(ep, &pfds[i], &timeout);
		if (timeout >= 0) {
			if (min_timeout < 0 ||
			    timeout < min_timeout) {
				min_timeout = timeout;
			}
		}
		i++;
	}


	*countp = i;
	*timeoutp = min_timeout;
	return 0;
}

int
ar_ioctx_pfd_dispatch(ar_ioctx_t ioctx, struct pollfd *pfds, int count)
{
	ar_ioep_t ep;
	ar_ioep_t ep_next;
	int i;

	if (!ioctx || !pfds) {
		return EINVAL;
	}

	i = 0;
	for (ep = TAILQ_FIRST(&ioctx->icx_ep_list); ep; ep = ep_next) {
		if (i >= count) {
			break;
		}
		ep_next = TAILQ_NEXT(ep, iep_listent);
		(*ep->iep_drv->epd_poll_dispatch)(ep, &pfds[i]);
		i++;
	}
	return 0;
}


int
ar_ioctx_run(ar_ioctx_t ioctx)
{
	struct pollfd	pfdlist[32];
	struct pollfd	*pfds;
	struct pollfd	*pfd_new;
	int		pfderr;
	int		pollerr;
	int		pfdsize;
	int		newsize;
	int		pfdcount;
	int		err;
	int		count;
	int		tout;

	if (!ioctx) {
		return EINVAL;
	}

	pfds = pfdlist;
	pfdsize = 32;
	pfdcount = 0;
	pfderr = 0;
	pollerr = 0;

	for (;;) {
		err = ar_ioctx_pfd_count(ioctx, &count);
		if (err != 0) {
			break;
		}

		if (count <= 0) {
			/* we're done. No more events */
			err = 0;
			break;
		}

		if (count > pfdsize) {
			newsize = count + 32;
			if (pfds == pfdlist) {
				pfd_new = malloc(sizeof(struct pollfd) *
						 newsize);
			} else {
				pfd_new = realloc(pfds,
						  sizeof(struct pollfd) *
						  newsize);
			}
			if (!pfd_new) {
				/* FIXME: we should probably just start
				 * destroying vc connections here.
				 */
				pfderr++;
				if (pfderr > 1000) {
					err = ENOMEM;
					break;
				}
				sleep(1);
				continue;
			}
			pfds = pfd_new;
			pfdsize = newsize;
		}

		pfderr = 0;

		pfdcount = pfdsize;
		err = ar_ioctx_pfd_setup(ioctx, pfds, &pfdcount, &tout);
		if (err != 0) {
			break;
		}

		err = poll(pfds, pfdcount, tout);
		if (err >= 0) {
			err = ar_ioctx_pfd_dispatch(ioctx, pfds, pfdcount);
		} else {
			err = errno;
			pollerr++;
			if (pollerr > 1000) {
				break;
			} else {
				sleep(1);
				continue;
			}
		}
		if (err != 0) {
			break;
		}
		pollerr = 0;
	}

	if (pfds != pfdlist) {
		free(pfds);
	}

	return err;
}


int
ar_ioctx_loop(ar_ioctx_t ioctx)
{
	struct pollfd	pfdlist[32];
	struct pollfd	*pfds;
	struct pollfd	*pfd_new;
	int		pfderr;
	int		pollerr;
	int		pfdsize;
	int		newsize;
	int		pfdcount;
	int		err;
	int		count;
	int		tout;

	if (!ioctx) {
		return EINVAL;
	}

	pfds = pfdlist;
	pfdsize = 32;
	pfdcount = 0;
	pfderr = 0;
	pollerr = 0;

	err = ar_ioctx_pfd_count(ioctx, &count);
	if (err != 0) {
		return err;
	}

	if (count <= 0) {
		/* we're done. No more events */
		return 0;
	}

	if (count > pfdsize) {
		newsize = count;
		pfd_new = malloc(sizeof(struct pollfd) * newsize);
		if (!pfd_new) {
			return ENOMEM;
		}
		pfds = pfd_new;
		pfdsize = newsize;
	}

	pfderr = 0;

	pfdcount = pfdsize;
	err = ar_ioctx_pfd_setup(ioctx, pfds, &pfdcount, &tout);
	if (err != 0) {
		goto cleanup;
	}

	err = poll(pfds, pfdcount, tout);
	if (err >= 0) {
		err = ar_ioctx_pfd_dispatch(ioctx, pfds, pfdcount);
	} else {
		err = errno;
	}
 cleanup:
	if (pfds != pfdlist) {
		free(pfds);
	}

	return err;
}

#ifdef HAVE_LIBEVENT
int
ar_ioctx_event_setup(ar_ioctx_t ioctx, struct event_base *evbase)
{
	ar_ioep_t ep;

	RPCTRACE(ioctx, 2, "ar_ioctx_event_setup(%p)\n", ioctx);
	ep = TAILQ_FIRST(&ioctx->icx_ep_list);
	while (ep != NULL) {
		if (!ep->iep_event) {
			RPCTRACE(ioctx, 3, "event setup() ioep %p\n", ep);
			/* the event hasn't been setup yet. */
			(*ep->iep_drv->epd_event_setup)(ep, evbase);
		}
		ep = TAILQ_NEXT(ep, iep_listent);
	}
	return 0;
}

int
ar_ioctx_event_cleanup(ar_ioctx_t ioctx)
{
	ar_ioep_t ep;

	ep = TAILQ_FIRST(&ioctx->icx_ep_list);
	while (ep != NULL) {
		if (ep->iep_event) {
			event_del(ep->iep_event);
			event_free(ep->iep_event);
			ep->iep_event = NULL;
		}
		ep = TAILQ_NEXT(ep, iep_listent);
	}
	return 0;
}
#endif

int
ar_ioctx_set_verbose(ar_ioctx_t ioctx, int level)
{
	if (!ioctx) {
		return EINVAL;
	}
	
	ioctx->icx_verbose = level;
	return 0;
}

void
ar_ioctx_dump(ar_ioctx_t ioctx, FILE *fp)
{
	ar_ioep_t ioep;
	ar_client_t *cl;
	ar_clnt_call_obj_t cco;

	if (!ioctx || !fp) {
		return;
	}

	fprintf(fp, "ioctx(%p)\n", ioctx);
	fprintf(fp, "  verbose=%u\n", ioctx->icx_verbose);
	TAILQ_FOREACH(ioep, &ioctx->icx_ep_list, iep_listent) {
		fprintf(fp, "  ioep(%p)\n", ioep);
		fprintf(fp, "\tiep_type=%u\n", ioep->iep_type);
		fprintf(fp, "\tiep_refcnt=%u\n", ioep->iep_refcnt);
		fprintf(fp, "\tiep_flags=%x\n", ioep->iep_flags);
		TAILQ_FOREACH(cl, &ioep->iep_client_list, cl_listent) {
			fprintf(fp, "\t  cl(%p)\n", cl);
		}
		TAILQ_FOREACH(cco, &ioep->iep_clnt_calls, cco_listent) {
			fprintf(fp, "\t  cco(%p)\n", cco);
		}
	}
	return;
}

void
ar_ioep_destroy(ar_ioep_t ep)
{
	if (!ep) {
		return;
	}

	(*ep->iep_drv->epd_destroy)(ep);
}

int
ar_ioep_init(ar_ioep_t ep, ar_ioctx_t ioctx, ar_ioep_type_t type,
	     ep_driver_t *drv, void *drv_arg, FILE *fp, const char *prefix)
{
	char *pdup;

	if (prefix) {
		pdup = strdup(prefix);
		if (!pdup) {
			return ENOMEM;
		}
	} else {
		pdup = NULL;
	}

	memset(ep, 0, sizeof(*ep));
	ep->iep_type = type;
	ep->iep_drv = drv;
	ep->iep_drv_arg = drv_arg;
	ep->iep_ioctx = ioctx;
	ep->iep_auth = ar_authnone_create();
	if (!ep->iep_auth) {
		if (pdup) {
			free(pdup);
		}
		return ENOMEM;
	}

	ep->iep_debug_file = fp;
	ep->iep_debug_prefix = pdup;

	TAILQ_INIT(&ep->iep_client_list);
	TAILQ_INIT(&ep->iep_clnt_calls);
	TAILQ_INIT(&ep->iep_svc_async_calls);
	TAILQ_INIT(&ep->iep_svc_replies);

	ar_xid_init(&ep->iep_xid_state);

	return 0;
}

void
ar_ioep_fatal_error(ar_ioep_t ep)
{
	if (!ep || !ep->iep_drv || !ep->iep_drv->epd_destroy) {
		syslog(LOG_ERR, "rpc: no destroy for endpoint");
		return;
	}

	(*ep->iep_drv->epd_destroy)(ep);
}

void
ar_ioep_cleanup(ar_ioep_t ep)
{

	if (ep->iep_auth) {
		ar_auth_destroy(ep->iep_auth);
	}
	if (ep->iep_debug_prefix) {
		free(ep->iep_debug_prefix);
		ep->iep_debug_prefix = NULL;
	}
}


/*
 * Local Variables:
 * tab-width:8
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 *
 */
