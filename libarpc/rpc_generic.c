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
 * rpc_generic.c, Miscl routines for RPC.
 *
 */

#include "compat.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libarpc/arpc.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <syslog.h>
#include "rpc_com.h"

static ar_netid_t ar_netids[] = {
	{"udp6", AF_INET6, AR_SEM_CLTS, IPPROTO_UDP, "inet6", 
	 "udp"},
	{"tcp6", AF_INET6, AR_SEM_COTS, IPPROTO_TCP, "inet6", 
	 "tcp"},
	{"udp", AF_INET, AR_SEM_CLTS, IPPROTO_UDP, "inet", "udp"},
	{"tcp", AF_INET, AR_SEM_COTS, IPPROTO_TCP, "inet", 
	 "tcp"},
	{"local", AF_LOCAL, AR_SEM_COTS, 0, "loopback", NULL},
	{NULL, AF_LOCAL}
};

/*
 * Find the appropriate buffer size
 */
u_int
ar_get_t_size(int af, int proto, int size)
{
	int maxsize, defsize;

	maxsize = 256 * 1024;	/* XXX */
	switch (proto) {
	case IPPROTO_TCP:
		defsize = 2 * 1024;	/* XXX */
		break;
	case IPPROTO_UDP:
		defsize = UDPMSGSIZE;
		break;
	default:
		defsize = RPC_MAXDATASIZE;
		break;
	}
	if (size == 0) {
		return defsize;
	}

	/* Check whether the value is within the upper max limit */
	return (size > maxsize ? (u_int)maxsize : (u_int)size);
}

/*
 * Find the appropriate address buffer size
 */
int
ar_get_a_size(sa_family_t af, int *sizep)
{
	switch (af) {
	case AF_INET:
		*sizep = sizeof(struct sockaddr_in);
		return 0;
	case AF_INET6:
		*sizep = sizeof(struct sockaddr_in6);
		return 0;
	case AF_LOCAL:
		*sizep = sizeof (struct sockaddr_un);
		return 0;
	default:
		break;
	}
	return EINVAL;
}

/*
 * Used to ping the NULL procedure for clnt handle.
 * Returns NULL if fails, else a non-NULL pointer.
 */
void *
rpc_nullproc(ar_client_t *clnt)
{
	struct timespec tout = {25, 0};

	if (ar_clnt_call(clnt, AR_NULLPROC, (axdrproc_t)axdr_void, NULL,
			 (axdrproc_t)axdr_void, NULL, 
			 0, &tout, NULL) != ARPC_SUCCESS) {
		return (NULL);
	}
	return ((void *)clnt);
}

int
ar_str2netid(ar_ioctx_t ioctx, const char *netid, ar_netid_t **infop)
{
	ar_netid_t *nid;
	int i;

	if (!ioctx || !netid || !infop) {
		return EINVAL;
	}

	for (i = 0; ar_netids[i].an_netid != NULL; i++) {
		if (strcmp(ar_netids[i].an_netid, netid) == 0) {
			*infop = &ar_netids[i];
			return 0;
		}
	}

	/* look through app-provided netid's for a match */
	for (nid = ioctx->icx_netid_list; nid; nid = nid->an_next) {
		if (strcmp(nid->an_netid, netid) == 0) {
			*infop = nid;
			return 0;
		}
	}

	return ENOENT;
}

int
ar_idx2netid(ar_ioctx_t ioctx, int idx, ar_netid_t **infop)
{
	ar_netid_t *nid;
	int i;

	if (!ioctx || !infop) {
		return EINVAL;
	}

	for (i = 0; ar_netids[i].an_netid != NULL; i++) {
		if (i == idx) {
			*infop = &ar_netids[i];
			return 0;
		}
	}

	/* look through app-provided netid's for a match */
	for (nid = ioctx->icx_netid_list; nid; nid = nid->an_next, i++) {
		if (i == idx) {
			*infop = nid;
			return 0;
		}
	}

	/* return null for end of iteration */
	*infop = NULL;
	return 0;
}

int
ar_class2netidstr(ar_ioctx_t ioctx, int semantics, sa_family_t fam,
		  const char **netidp)
{
	ar_netid_t *nid;
	int i;

	if (!ioctx || !netidp) {
		return EINVAL;
	}

	for (i = 0; ar_netids[i].an_netid != NULL; i++) {
		if (ar_netids[i].an_family == fam &&
		    ar_netids[i].an_semantics == semantics) {
			*netidp = ar_netids[i].an_netid;
			return 0;
		}
	}

	/* look through app-provided netid's for a match */
	for (nid = ioctx->icx_netid_list; nid; nid = nid->an_next) {
		if (nid->an_family == fam && nid->an_semantics == semantics) {
			*netidp = nid->an_netid;
			return 0;
		}
	}

	return ENOENT;
}

int
ar_family2proto(sa_family_t family, int type, int *protop)
{
	/* XXX */
	if (family != AF_LOCAL) {
		if (type == SOCK_STREAM) {
			*protop = IPPROTO_TCP;
		} else if (type == SOCK_DGRAM) {
			*protop = IPPROTO_UDP;
		} else {
			return EINVAL;
		}
	} else {
		*protop = 0;
	}

	return 0;
}

int
ar_fd2sockinfo(int fd, ar_sockinfo_t *sip)
{
	socklen_t len;
	int type;
	struct sockaddr_storage ss;
	int err;

	len = sizeof(ss);
	memset(&ss, 0, sizeof(ss));

	err = getsockname(fd, (struct sockaddr *)(void *)&ss, &len);
	if (err < 0) {
		err = errno;
		return err;
	}
	sip->si_alen = len;

	len = sizeof(type);
	err = getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len);
	if (err < 0) {
		err = errno;
		return err;
	}

	sip->si_af = ss.ss_family;
	sip->si_socktype = type;

	err = ar_family2proto(ss.ss_family, type, &sip->si_proto);
	if (err != EOK) {
		return err;
	}

	return 0;
}

int
ar_sem2socktype(int sem, int *typep)
{
	switch (sem) {
	case AR_SEM_COTS:
		*typep = SOCK_STREAM;
		return 0;
	case AR_SEM_CLTS:
		*typep = SOCK_DGRAM;
		return 0;
	default:
		break;
	}

	return EINVAL;
}

int 
ar_netid2sockinfo(const ar_netid_t *netid, ar_sockinfo_t *sip)
{
	int err;

	sip->si_af = netid->an_family;
	err = ar_sem2socktype(netid->an_semantics, &sip->si_socktype);
	if (err != 0) {
		return err;
	}
	err = ar_family2proto(sip->si_af, sip->si_socktype, &sip->si_proto);
	if (err != 0) {
		return err;
	}
	err = ar_get_a_size(sip->si_af, &sip->si_alen);
	if (err != 0) {
		return err;
	}
	return 0;
}


/*
 * Linear search, but the number of entries is small.
 */
int
ar_str2sockinfo(struct ar_ioctx_s *ioctx, const char *netid, 
		ar_sockinfo_t *sip)
{
	ar_netid_t *info;
	int err;

	err = ar_str2netid(ioctx, netid, &info);
	if (err != 0) {
		return err;
	}

	return ar_netid2sockinfo(info, sip);
}

int
ar_sockinfo2netid(ar_sockinfo_t *sip, const char **netidp)
{
	ar_netid_t *info = NULL;

	if (!sip || !netidp) {
		return EINVAL;
	}

	*netidp = info->an_netid;
	return 0;
}

int
ar_taddr2uaddr(struct ar_ioctx_s *ioctx, const char *netid, 
	       const arpc_addr_t *addr, char **retp)
{
	ar_netid_t *info;
	int err;

	if (!netid || !addr || !retp) {
		return EINVAL;
	}

	err = ar_str2netid(ioctx, netid, &info);
	if (err != EOK) {
		return err;
	}

	return ar_taddr2uaddr_af(info->an_family, addr, retp);
}

int
ar_uaddr2taddr(struct ar_ioctx_s *ioctx, const char *netid,
	       const char *uaddr, arpc_addr_t **retp)
{
	ar_netid_t *info;
	int err;

	if (!netid || !uaddr || !retp) {
		return EINVAL;
	}

	err = ar_str2netid(ioctx, netid, &info);
	if (err != EOK) {
		return err;
	}

	return ar_uaddr2taddr_af(info->an_family, uaddr, retp);
}

static int
ar_uaddrport(u_int16_t port, const char *name, char **retp)
{
	char pbuf[16];
	char *ret;
	int len;

	/* convert to host order */
	port = ntohs(port);

	snprintf(pbuf, sizeof(pbuf), ".%u.%u", ((u_int32_t)port) >> 8,
		 port & 0xff);
	len = strlen(pbuf) + strlen(name) + 1;
	ret = malloc(len);
	if (!ret) {
		return ENOMEM;
	}
	snprintf(ret, len, "%s%s", name, pbuf);
	*retp = ret;
	return EOK;
}

int
ar_taddr2uaddr_af(sa_family_t af, const arpc_addr_t *nbuf, char **retp)
{
	char *ret;
	struct sockaddr_in *sin;
	struct sockaddr_un *sun;
	char namebuf[INET_ADDRSTRLEN];
	struct sockaddr_in6 *sin6;
	char namebuf6[INET6_ADDRSTRLEN];
	int len;
	int err;

	if (!nbuf || !retp) {
		return EINVAL;
	}

	switch (af) {
	case AF_INET:
		sin = (struct sockaddr_in *)nbuf->buf;
		if (inet_ntop(af, &sin->sin_addr, namebuf, sizeof namebuf)
		    == NULL) {
			return EPARSE;
		}
		err = ar_uaddrport(sin->sin_port, namebuf, &ret);
		if (err != EOK) {
			return err;
		}
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)nbuf->buf;
		if (inet_ntop(af, &sin6->sin6_addr, namebuf6, sizeof namebuf6)
		    == NULL) {
			return EPARSE;
		}
		err = ar_uaddrport(sin6->sin6_port, namebuf6, &ret);
		if (err != EOK) {
			return err;
		}
		break;
	case AF_LOCAL:
		sun = (struct sockaddr_un *)nbuf->buf;
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
		len = sun->sun_len - offsetof(struct sockaddr_un, sun_path);
#else
		len = sizeof(*sun) - offsetof(struct sockaddr_un, sun_path);
#endif
		len = strnlen(sun->sun_path, len);
		ret = malloc(len + 1);
		if (!ret) {
			return ENOMEM;
		}
		snprintf(ret, len+1, "%.*s", len, sun->sun_path);
		break;
	default:
		return EINVAL;
	}

	*retp = ret;
	return 0;
}

int
ar_uaddr2taddr_af(int af, const char *uaddr, arpc_addr_t **retp)
{
	arpc_addr_t *ret = NULL;
	char *addrstr, *p;
	unsigned port, portlo, porthi;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr_un *sun;
	int err;

	if (!uaddr || !retp) {
		return EINVAL;
	}

	port = 0;
	sin = NULL;
	addrstr = strdup(uaddr);
	if (addrstr == NULL) {
		return ENOMEM;
	}

	/*
	 * AF_LOCAL addresses are expected to be absolute
	 * pathnames, anything else will be AF_INET or AF_INET6.
	 */
	if (*addrstr != '/') {
		p = strrchr(addrstr, '.');
		if (p == NULL) {
			err = EINVAL;
			goto out;
		}
		portlo = (unsigned)atoi(p + 1);
		*p = '\0';

		p = strrchr(addrstr, '.');
		if (p == NULL) {
			err = EINVAL;
			goto out;
		}
		porthi = (unsigned)atoi(p + 1);
		*p = '\0';
		port = (porthi << 8) | portlo;
	}

	ret = (arpc_addr_t *)malloc(sizeof(*ret));
	if (ret == NULL) {
		err = ENOMEM;
		goto out;
	}
	memset(ret, 0, sizeof(*ret));

	err = 0;
	switch (af) {
	case AF_INET:
		sin = (struct sockaddr_in *)malloc(sizeof *sin);
		if (sin == NULL) {
			err = ENOMEM;
			goto out;
		}
		memset(sin, 0, sizeof *sin);
		ret->buf = (char *)sin;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		if (inet_pton(AF_INET, addrstr, &sin->sin_addr) <= 0) {
			err = EPARSE;
			goto out;
		}
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
		sin->sin_len = ret->maxlen = ret->len = sizeof *sin;
#endif
		ret->len = sizeof(*sin);
		ret->maxlen = sizeof(*sin);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)malloc(sizeof *sin6);
		if (sin6 == NULL) {
			err = ENOMEM;
			goto out;
		}
		memset(sin6, 0, sizeof *sin6);
		ret->buf = (char *)sin6;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		if (inet_pton(AF_INET6, addrstr, &sin6->sin6_addr) <= 0) {
			err = EPARSE;
			goto out;
		}
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
		sin6->sin6_len = ret->maxlen = ret->len = sizeof *sin6;
#endif
		ret->len = sizeof(*sin6);
		ret->maxlen = sizeof(*sin6);
		break;
	case AF_LOCAL:
		sun = (struct sockaddr_un *)malloc(sizeof *sun);
		if (sun == NULL) {
			err = ENOMEM;
			goto out;
		}
		memset(sun, 0, sizeof *sun);
		ret->buf = (char *)sun;
		sun->sun_family = AF_LOCAL;
		strlcpy(sun->sun_path, addrstr, sizeof(sun->sun_path));
		ret->len = ret->maxlen = SUN_LEN(sun);
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
		sun->sun_len = ret->len;
#endif
		ret->len = sizeof(*sun);
		ret->maxlen = sizeof(*sun);
		break;
	default:
		err = EINVAL;
		break;
	}
out:
	free(addrstr);
	if (err == EOK) {
		*retp = ret;
	} else if (ret) {
		if (ret->buf) {
			free(ret->buf);
			ret->buf = NULL;
		}
		free(ret);
	}
	return err;
}

/*
 * XXXX - IPv6 scope IDs can't be handled in universal addresses.
 * Here, we compare the original server address to that of the RPC
 * service we just received back from a call to rpcbind on the remote
 * machine. If they are both "link local" or "site local", copy
 * the scope id of the server address over to the service address.
 */
int
ar_fixup_addr(arpc_addr_t *new, const arpc_addr_t *svc)
{
	struct sockaddr *sa_new, *sa_svc;
	struct sockaddr_in6 *sin6_new, *sin6_svc;

	sa_svc = (struct sockaddr *)svc->buf;
	sa_new = (struct sockaddr *)new->buf;

	if (sa_new->sa_family == sa_svc->sa_family &&
	    sa_new->sa_family == AF_INET6) {
		sin6_new = (struct sockaddr_in6 *)new->buf;
		sin6_svc = (struct sockaddr_in6 *)svc->buf;

		if ((IN6_IS_ADDR_LINKLOCAL(&sin6_new->sin6_addr) &&
		     IN6_IS_ADDR_LINKLOCAL(&sin6_svc->sin6_addr)) ||
		    (IN6_IS_ADDR_SITELOCAL(&sin6_new->sin6_addr) &&
		     IN6_IS_ADDR_SITELOCAL(&sin6_svc->sin6_addr))) {
			sin6_new->sin6_scope_id = sin6_svc->sin6_scope_id;
		}
	}
	return 0;
}

int
ar_sockisbound(int fd, bool_t *boundp)
{
	struct sockaddr_storage ss;
	socklen_t slen;
	int err;

	slen = sizeof (struct sockaddr_storage);
	err = getsockname(fd, (struct sockaddr *)(void *)&ss, &slen);
	if (err < 0) {
		err = errno;
		return err;
	}

	switch (ss.ss_family) {
	case AF_INET:
		*boundp = (((struct sockaddr_in *)
			    (void *)&ss)->sin_port != 0);
		return 0;
	case AF_INET6:
		*boundp = (((struct sockaddr_in6 *)
			    (void *)&ss)->sin6_port != 0);
		return 0;
	case AF_LOCAL:
		/* XXX check this */
		*boundp = (((struct sockaddr_un *)
			    (void *)&ss)->sun_path[0] != '\0');
		return 0;
	default:
		break;
	}

	return EINVAL;
}

/*
 * Make sure that the time is not garbage.   -1 value is disallowed.
 */
bool_t
ar_time_not_ok(struct timespec *t)
{
	return (t->tv_sec <= -1 || t->tv_sec > 100000000 ||
		t->tv_nsec <= -1 || t->tv_nsec > 1000000000);
}

int
ar_gettime(struct timespec *res)
{
	int sts;
	struct timeval tv;

	if (!res) {
		errno = EINVAL;
		return -1;
	}

#ifdef HAVE_CLOCK_MONOTONIC
	sts = clock_gettime(CLOCK_MONOTONIC, res);
	if (sts == 0) {
		return sts;
	}
#endif

	/* use gettimeofday as a backup */
	sts = gettimeofday(&tv, NULL);
	if (sts != 0) {
		return sts;
	}
	res->tv_sec = tv.tv_sec;
	res->tv_nsec = tv.tv_usec * 1000;
	return 0;
}

int
ar_time_to_ms(struct timespec *diff)
{
	struct timespec zero;
	int period;

	zero.tv_sec = 0;
	zero.tv_nsec = 0;

	if (tspeccmp(diff, &zero, <=)) {
		/* expired */
		period = 0;
	} else if (diff->tv_sec > 2000000) {
		/* cap at 2e6 seconds */
		period = 2000000000;
	} else {
		period = diff->tv_sec * 1000;
		period += diff->tv_nsec / 1000000;
	}

	return period;
}

int
ar_tsaddmsecs(struct timespec *ts, int msecs)
{
	if (!ts) {
		errno = EINVAL;
		return -1;
	}

	ts->tv_sec += msecs / 1000;
	ts->tv_nsec += (msecs % 1000) * 1000000;
	if (ts->tv_nsec >= 1000000000L) {
		ts->tv_sec++;
		ts->tv_nsec -= 1000000000L;
	}
	return 0;
}

void
ar_xid_init(struct ar_xid_state_s *state)
{
	uint32_t	val;
	uint32_t	array[4];
	int		err;
	int		fd;

	val = (uint32_t)time(NULL);
	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		err = errno;
		fprintf(stderr, "unable to open /dev/random: %s\n", 
			strerror(err));
		state->nextxid = val;
		return;
	}

	err = read(fd, array, sizeof(array));
	if (err < sizeof(val)) {
		if (err < 0) {
			err = errno;
			fprintf(stderr, "unable to read /dev/random: %s\n", 
				strerror(err));
		} else {
			fprintf(stderr, "short read from /dev/random\n");
		}
		state->nextxid = val;
		close(fd);
		return;
	}
	close(fd);

	val ^= array[0];
	val ^= array[1];
	val ^= array[2];
	val ^= array[3];
	
	
	state->nextxid = val;
	return;
}

uint32_t
ar_xid_get(struct ar_xid_state_s *state)
{
	uint32_t val;

	val = state->nextxid;
	state->nextxid = val + 1;
	return val;
}

void
ar_log_msg(ar_ioep_t ioep, arpc_msg_t *msg, const char *heading)
{
	char prefix[80];
	int err;
	axdr_state_t xdr;

	if (!ioep->iep_debug_file) {
		return;
	}

	fprintf(ioep->iep_debug_file, "%s%s\n", ioep->iep_debug_prefix ?
		ioep->iep_debug_prefix : "", heading);


	snprintf(prefix, sizeof(prefix), "%smsg", 
		 ioep->iep_debug_prefix ? 
		 ioep->iep_debug_prefix : "");


	err = axdr_fprint_create(&xdr, ioep->iep_debug_file, prefix);
	if (err != 0) {
		return;
	}

	axdr_msg(&xdr, msg);
	axdr_destroy(&xdr);
}


void
ar_errno2err(arpc_err_t *errp, int err)
{
	if (!errp) {
		return;
	}

	memset(errp, 0, sizeof(*errp));

	switch (err) {
	case 0:
		errp->re_status = ARPC_SUCCESS;
		break;
	case EHOSTDOWN:
	case EHOSTUNREACH:
	case ENETUNREACH:
		errp->re_status = ARPC_UNKNOWNADDR;
		break;
	default:
		errp->re_status = ARPC_ERRNO;
		break;
	}
	errp->re_errno = err;
}

#ifndef HAVE_CLOCK_GETTIME
int
clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	struct timeval tv;
	int rval;

	if (!tp) {
		errno = EINVAL;
		return -1;
	}

	rval = gettimeofday(&tv, NULL);
	if (rval != 0) {
		return rval;
	}

	tp->tv_sec  = tv.tv_sec;
	tp->tv_nsec = tv.tv_usec * 1000;
	return 0;
}
#endif

#ifndef HAVE_STRNLEN
size_t
strnlen(const char *s, size_t maxlen)
{
	size_t i;

	if (!s) {
		return 0;
	}

	for (i = 0; i < maxlen; i++) {
		if (s[i] == '\0') {
			return i;
		}
	}
	return maxlen;
}
#endif

/* copyright for the below BSD libc functions: */		
/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND TODD C. MILLER DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL TODD C. MILLER BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
	
/* define standard functions if they are missing */
#ifndef HAVE_STRLCAT
size_t
strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}
#endif

#ifndef HAVE_STRLCPY
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}
#endif


