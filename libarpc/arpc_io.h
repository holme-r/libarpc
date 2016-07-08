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

#ifndef _LIBARPC_ARPC_IO_H
#define	_LIBARPC_ARPC_IO_H

#include <sys/cdefs.h>
#ifdef HAVE_LIBEVENT
#include <event.h>
#endif

/* SOME legacy defines:
 *
 */
#define UDPMSGSIZE      8800    /* arpc imposed limit on udp msg size */

__BEGIN_DECLS
/* generic interface for streaming bottom end */
typedef int (*ar_vcd_readfn_t)(void *vc, struct iovec *vector, 
			       int count, size_t *lenp);
typedef int (*ar_vcd_writefn_t)(void *vc, const struct iovec *vector, 
				int count, size_t *lenp);
typedef int (*ar_vcd_closefn_t)(void *vc);
typedef int (*ar_vcd_cntrlfn_t)(void *vc, u_int request, void *info);

/* poll callback: on input it's what the upper layer wants.  On return, it's
 * what bits the fd should be polled on.
 */
struct pollfd;
typedef int (*ar_vcd_psetupfn_t)(void *vc, struct pollfd *pfd, int *timeoutp);

/* Called will poll results (revents set).  On return, contains revents for
 * upper layer.
 */
struct ar_clnt_attr_s;
struct ar_svc_attr_s;
struct arpc_createerr_s;
typedef int (*ar_vcd_pdispatchfn_t)(void *vc, struct pollfd *pfd);
typedef int (*ar_vcd_getfdfn_t)(void *vc, int *fdp);
typedef int (*ar_vcd_connfn_t)(void *vc, const arpc_addr_t *, 
			       struct arpc_createerr_s *errp);
typedef int (*ar_vcd_accept_t)(void *vc, void **vcpp);
typedef int (*ar_vcd_getladdr_t)(void *vc, arpc_addr_t *nb);
typedef int (*ar_vcd_getfamily_t)(void *vc, sa_family_t *famp);
typedef int (*ar_vcd_fromfd_t)(struct ar_svc_attr_s *svc_attr, 
			       int fd, void **streampp);
typedef int (*ar_vcd_islistener_t)(void *vc, bool_t *listenp);
typedef int (*ar_vcd_listen_t)(void *vc, const arpc_addr_t *addr);
typedef int (*ar_vcd_init_t)(struct ar_clnt_attr_s *clnt_attr, 
			     struct ar_svc_attr_s *svc_attr, void **vcp);
typedef int (*ar_vcd_destroy_t)(void *vcp);
typedef int (*ar_vcd_gettmout_t)(void *vc, struct timespec *tmout);
typedef struct ar_vcd_s *ar_vcd_t;

extern int ar_vcd_create(ar_vcd_t *retp);
extern void ar_vcd_destroy(ar_vcd_t vcd);
extern int ar_vcd_set_write(ar_vcd_t vcd, ar_vcd_writefn_t);
extern int ar_vcd_set_read(ar_vcd_t vcd, ar_vcd_readfn_t);
extern int ar_vcd_set_close(ar_vcd_t vcd, ar_vcd_closefn_t);
extern int ar_vcd_set_control(ar_vcd_t vcd, ar_vcd_cntrlfn_t);
extern int ar_vcd_set_connect(ar_vcd_t vcd, ar_vcd_connfn_t);
extern int ar_vcd_set_shutdown(ar_vcd_t vcd, ar_vcd_closefn_t);
extern int ar_vcd_set_pollsetup(ar_vcd_t vcd, ar_vcd_psetupfn_t);
extern int ar_vcd_set_polldispatch(ar_vcd_t vcd, ar_vcd_pdispatchfn_t);
extern int ar_vcd_set_getfd(ar_vcd_t vcd, ar_vcd_getfdfn_t);
extern int ar_vcd_set_fromfd(ar_vcd_t vcd, ar_vcd_fromfd_t);

extern int ar_vcd_set_accept(ar_vcd_t vcd, ar_vcd_accept_t);
extern int ar_vcd_set_init(ar_vcd_t vcd, ar_vcd_init_t);
extern int ar_vcd_set_destroy(ar_vcd_t vcd, ar_vcd_destroy_t);
extern int ar_vcd_set_getladdr(ar_vcd_t vcd, ar_vcd_getladdr_t);
extern int ar_vcd_set_getfamily(ar_vcd_t vcd, ar_vcd_getfamily_t);
extern int ar_vcd_set_islistener(ar_vcd_t vcd, ar_vcd_islistener_t);
extern int ar_vcd_set_listen(ar_vcd_t vcd, ar_vcd_listen_t);

struct ar_ioctx_s;
struct ar_ioep_s;
typedef struct ar_ioctx_s *ar_ioctx_t;	/* set of endpoints */
typedef struct ar_ioep_s *ar_ioep_t;		/* single endpoint */
extern int ar_ioctx_create(ar_ioctx_t *ioctxp);

extern int ar_ioctx_add_vcd(ar_ioctx_t ioctx, ar_vcd_t vcd, 
			    const char *netid);
extern int ar_ioctx_remove_vcd(ar_ioctx_t ioctx, const char *proto);
/* pfd specific interface should eventually become more generic */
extern int ar_ioctx_pfd_count(ar_ioctx_t ioctx, int *countp);
extern int ar_ioctx_pfd_setup(ar_ioctx_t ioctx, 
			       struct pollfd *pfds, int *countp, 
			       int *timeoutp);
extern int ar_ioctx_pfd_dispatch(ar_ioctx_t ioctx, 
				  struct pollfd *pfds, int count);
extern int ar_ioctx_pfd_timeout(ar_ioctx_t ioctx);
extern int ar_ioctx_loop(ar_ioctx_t ioctx);
extern int ar_ioctx_run(ar_ioctx_t ioctx);

#ifdef HAVE_LIBEVENT
extern int ar_ioctx_event_setup(ar_ioctx_t ioctx, struct event_base *evbase);
extern int ar_ioctx_event_cleanup(ar_ioctx_t ioctx);
#endif

extern void ar_ioctx_destroy(ar_ioctx_t ioctx);
extern void ar_ioctx_dump(ar_ioctx_t ioctx, FILE *fp);
extern void ar_ioep_destroy(ar_ioep_t ep);

extern int ar_ioctx_set_verbose(ar_ioctx_t ioctx, int level);

/**
 * Lookup correct connection oriented transport driver
 *
 * @param nconf - netconfig entry to lookup transport driver for.
 * @param drv - pointer to return vcd in.
 * @return - 0 on success.  Errno value on failure.
 */
extern int ar_vcd_lookup(ar_ioctx_t ioctx, const char *protoid,
			 ar_vcd_t *drv);
extern int ar_vcd_default(ar_vcd_t *drv);
extern int ar_vcd_fromfd(struct ar_svc_attr_s *attr, ar_vcd_t drv, 
			 int fd, void **streampp);
extern int ar_vcd_listen(ar_vcd_t drv, const arpc_addr_t *addr, 
			 void **streampp);
extern void ar_vcd_close(ar_vcd_t drv, void *stream);

__END_DECLS

#endif /* _LIBARPC_ARPC_IO_H */
