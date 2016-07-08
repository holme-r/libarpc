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

#include "compat.h"

#include <sys/param.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <assert.h>
#include <libarpc/stack.h>
#include <string.h>
#include <errno.h>
#include <libarpc/arpc.h>
#include <libarpc/arpc_io.h>
#include <libarpc/vcd_tls.h>
#include "rpc_com.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

typedef enum vcd_tls_state_e {
	VCDD_STATE_CLOSED = 1,
	VCDD_STATE_CONNECTING,
	VCDD_STATE_ESTABLISHED,
	VCDD_STATE_SHUTDOWN,
	VCDD_STATE_LISTEN,
	VCDD_STATE_ERROR,
	VCDD_STATE_SSL_HANDSHAKE
} vcd_tls_state_t;

typedef enum tls_conn_mode_e {
	TLS_CONN_CLIENT,
	TLS_CONN_SERVER
} tls_conn_mode_t;

typedef struct vcd_tls_ctx_s {
	vcd_tls_state_t		vdc_state;
	int			vdc_fd;
	char			vdc_buf[8];
	int			vdc_bufcnt;
	int			vdc_err;
	int			vdc_events;
	/* Assembled for TLS support */
	SSL			*vdc_ssl;
	SSL_CTX			*vdc_ssl_ctx;
	PKCS12			*vdc_pkcs12;
	uint32_t		vdc_tls_flags;
	char			*vdc_passwd;
	void			*vdc_tls_arg;
	struct timespec		vdc_tls_timeout;
	ar_tls_setup_cb_t	vdc_tls_setup;
	ar_tls_verify_cb_t	vdc_tls_verify;
	ar_tls_info_cb_t	vdc_tls_info;
} vcd_tls_ctx_t;

static int vcd_tls_read(void *vc, struct iovec *vector, int count,
			size_t *lenp);
static int vcd_tls_write(void *vc, const struct iovec *vector, int count,
			 size_t *lenp);
static int vcd_tls_close(void *vc);
static int vcd_tls_shutdown(void *vc);
static int vcd_tls_control(void *vc, u_int request, void *info);
static int vcd_tls_poll_setup(void *vc, struct pollfd *pfd, int *timeoutp);
static int vcd_tls_poll_dispatch(void *vc, struct pollfd *pfd);
static int vcd_tls_getfd(void *vc, int *fdp);
static int vcd_tls_fromfd(ar_svc_attr_t *svc_attr, int fd, void **vc);
static int vcd_tls_conn(void *vc, const arpc_addr_t *, 
			arpc_createerr_t *errp);
static int vcd_tls_accept(void *vc, void **vcpp);
static int vcd_tls_getladdr(void *vc, arpc_addr_t *nb);
static int vcd_tls_getfamily(void *vc, sa_family_t *famp);
static int vcd_tls_islistener(void *vc, bool_t *listenp);
static int vcd_tls_listen(void *vc, const arpc_addr_t *addr);
static int vcd_tls_init(ar_clnt_attr_t *clnt_attr, ar_svc_attr_t *svc_attr, void **vcpp);
static int vcd_tls_destroy(void *vcp);
static int vcd_get_ssl_error(char *errbuf, size_t errlen);
static int vcd_get_ssl_io_error(vcd_tls_ctx_t *ctx, int ret, char *errbuf, size_t errlen);
static int vcd_tls_sslctx_init(vcd_tls_ctx_t *ctx);
static int vcd_tls_do_handshake(vcd_tls_ctx_t *ctx, tls_conn_mode_t mode);
static int vcd_tls_sslctx_free(vcd_tls_ctx_t *ctx);
static int vcd_pkcs12_duplicate(PKCS12 *p12, PKCS12 **retp);
static int vcd_tls_get_timeout(void *vc, struct timespec *tmout);

static struct ar_vcd_s vcd_tls = {
	vcd_tls_read,
	vcd_tls_write,
	vcd_tls_close,
	vcd_tls_shutdown,
	vcd_tls_control,
	vcd_tls_poll_setup,
	vcd_tls_poll_dispatch,
	vcd_tls_getfd,
	vcd_tls_fromfd,
	vcd_tls_conn,
	vcd_tls_accept,
	vcd_tls_getladdr,
	vcd_tls_getfamily,
	vcd_tls_islistener,
	vcd_tls_listen,
	vcd_tls_init,
	vcd_tls_destroy,
	vcd_tls_get_timeout
};

static int
vcd_tls_read(void *vc, struct iovec *cvector, int count, size_t *lenp)
{
	vcd_tls_ctx_t *ctx;
	ssize_t ret;
	int err = EOK;
	char *cp;
	size_t len;
	size_t accum;
	struct iovec *vector;
	void *orig_base = NULL;
	int orig_len = -1;
	int i, j;
	char errbuf[256];

	if (!vc || !lenp || !cvector) {
		return EINVAL;
	}

	vector = (struct iovec *)cvector;
	ctx = (vcd_tls_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
	default:
		return ENOTCONN;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
	case VCDD_STATE_SSL_HANDSHAKE:
		return EAGAIN;
	case VCDD_STATE_SHUTDOWN:
	case VCDD_STATE_ESTABLISHED:
		break;
	}

	if (count <= 0) {
		*lenp = 0;
		return 0;
	}

	i = 0;
	accum = 0;

	/* copy buffered data first */
	while (ctx->vdc_bufcnt > 0) {
		len = vector[i].iov_len;
		if (len > ctx->vdc_bufcnt) {
			len = ctx->vdc_bufcnt;
		}
		memcpy(vector[i].iov_base, ctx->vdc_buf, len);
		if ((ctx->vdc_bufcnt - len) > 0) {
			memmove(ctx->vdc_buf, &ctx->vdc_buf[len], 
				ctx->vdc_bufcnt - len);
		}
		ctx->vdc_bufcnt -= len;
		accum += len;
		if (len >= vector[i].iov_len) {
			if (orig_base) {
				vector[i].iov_base = orig_base;
				vector[i].iov_len = orig_len;
				orig_base = NULL;
				orig_len = -1;
			}
			i++;
			if (i >= count) {
				*lenp = accum;
				return 0;
			}
		} else {
			if (!orig_base) {
				orig_base = vector[i].iov_base;
				orig_len = vector[i].iov_len;
			}
			vector[i].iov_len -= len;
			cp = vector[i].iov_base;
			vector[i].iov_base = &cp[len];
		}
	}

	for (j = i; j < count; j++) {
	retry:
		ret = SSL_read(ctx->vdc_ssl, vector[j].iov_base, 
			       vector[j].iov_len);
		if (ret < 0) {
			err = vcd_get_ssl_io_error(ctx, ret, 
						   errbuf, sizeof(errbuf));
			if (err == EINTR) {
				goto retry;
			} else if (err == EOK && ret == 0) {
				err = ESHUTDOWN;
			}
			break;
		} else {
			accum += ret;
			err = 0;
		}
	}

	if (orig_base) {
		vector[i].iov_base = orig_base;
		vector[i].iov_len = orig_len;
	}

	if (err != EOK) {
		*lenp = accum;
		if (accum > 0) {
			/* we got data. Have to indicate that */
			err = 0;
		}
	} else {
		*lenp = (size_t)accum;
		err = 0;
	}

	return err;
}

static int
vcd_tls_write(void *vc, const struct iovec *vector, int count, size_t *lenp)
{
	vcd_tls_ctx_t *ctx;
	ssize_t ret;
	int err = EOK;
	ssize_t total = 0;
	int i;
	struct iovec *vec;
	char errbuf[256];

	if (!vc || !lenp || !vector) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
	default:
		return ENOTCONN;
	case VCDD_STATE_SHUTDOWN:
		return EPIPE;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
	case VCDD_STATE_SSL_HANDSHAKE:
		return EAGAIN;
	case VCDD_STATE_ESTABLISHED:
		break;
	}

	if (count <= 0) {
		*lenp = 0;
		return 0;
	}

	for (i = 0, vec = (struct iovec *)vector; i < count; i++, vec++) {
	retry:
		ret = SSL_write(ctx->vdc_ssl, vec->iov_base, vec->iov_len);
		if (ret < 0) {
			err = vcd_get_ssl_io_error(ctx, ret, 
						   errbuf, sizeof(errbuf));
			if (err == EINTR) {
				goto retry;
			}
			break;
		} else {
			total += ret;
			err = 0;
		}
	}
	*lenp = (size_t)total;
	return err;
}

static int
vcd_tls_close(void *vc)
{
	vcd_tls_ctx_t *ctx;
	int ret;
	
	if (!vc) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
		return 0;
	default:
		return EIO;
	case VCDD_STATE_SHUTDOWN:
	case VCDD_STATE_CONNECTING:
	case VCDD_STATE_ESTABLISHED:
	case VCDD_STATE_LISTEN:
		ret = close(ctx->vdc_fd);
		if (ret < 0) {
			ret = errno;
		} else {
			ret = 0;
		}
		ctx->vdc_fd = -1;
		SSL_set_quiet_shutdown(ctx->vdc_ssl, 1);
		SSL_shutdown(ctx->vdc_ssl);
		vcd_tls_sslctx_free(ctx);
		ctx->vdc_state = VCDD_STATE_CLOSED;
		return ret;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	}
}

static int
vcd_tls_shutdown(void *vc)
{
	vcd_tls_ctx_t *ctx;
	int ret;
	
	if (!vc) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
	default:
		return ENOTCONN;
	case VCDD_STATE_SHUTDOWN:
		return 0;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
	case VCDD_STATE_ESTABLISHED:
	case VCDD_STATE_SSL_HANDSHAKE:
		ret = shutdown(ctx->vdc_fd, SHUT_WR);
		if (ret < 0) {
			ret = errno;
		} else {
			ret = 0;
		}

		SSL_set_quiet_shutdown(ctx->vdc_ssl, 1);
		SSL_shutdown(ctx->vdc_ssl);
		vcd_tls_sslctx_free(ctx);
		ctx->vdc_state = VCDD_STATE_SHUTDOWN;
		return ret;
	}
}

static int
vcd_tls_control(void *vc, u_int request, void *info)
{
	vcd_tls_ctx_t *ctx;
	arpc_addr_t *nb;
	int err;
	
	if (!vc) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;
	switch (request) {
	case AR_CLGET_CONNECTED: {
		bool_t conn;

		if (!info) {
			return EINVAL;
		}

		switch (ctx->vdc_state) {
		case VCDD_STATE_CLOSED:
		case VCDD_STATE_SHUTDOWN:
		case VCDD_STATE_ERROR:
		case VCDD_STATE_CONNECTING:
		case VCDD_STATE_SSL_HANDSHAKE:
		default:
			conn = FALSE;
			break;
		case VCDD_STATE_ESTABLISHED:
			conn = TRUE;
		}

		*((bool_t *)info) = conn;
		return 0;
	}
	case AR_CLGET_SERVER_ADDR:
		if (!info) {
			return EINVAL;
		}

		nb = (arpc_addr_t *)info;
		nb->len = nb->maxlen;
		err = getpeername(ctx->vdc_fd, (struct sockaddr *)nb->buf,
				  &nb->len);
		if (err < 0) {
			err = errno;
		} else {
			err = 0;
		}
		return err;
	case AR_CLGET_LOCAL_ADDR:
		if (!info) {
			return EINVAL;
		}

		nb = (arpc_addr_t *)info;
		nb->len = nb->maxlen;
		err = getsockname(ctx->vdc_fd, (struct sockaddr *)nb->buf,
				  &nb->len);
		if (err < 0) {
			err = errno;
		} else {
			err = 0;
		}
		return err;
	default:
		return ENOSYS;
	}
}

static int
vcd_tls_poll_setup(void *vc, struct pollfd *pfd, int *timeoutp)
{
	vcd_tls_ctx_t *ctx;
	BIO *wbio;
	BIO *rbio;

	if (!vc || !pfd || !timeoutp) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	pfd->fd = (int)ctx->vdc_fd;
	*timeoutp = -1;

	/* save off original requested events. */
	ctx->vdc_events = pfd->events;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
		pfd->fd = -1;
		pfd->events = 0;
		return 0;
	default:
		pfd->fd = -1;
		return ENOTCONN;
	case VCDD_STATE_SHUTDOWN:
		pfd->events &= ~POLLOUT;
		return 0;
	case VCDD_STATE_ERROR:
		pfd->fd = -1;
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
		pfd->events |= POLLOUT|POLLIN;
		return 0;
	case VCDD_STATE_SSL_HANDSHAKE:
		if (ctx->vdc_ssl) {
			wbio = SSL_get_wbio(ctx->vdc_ssl);
			if (wbio) {
				wbio = BIO_find_type(wbio, BIO_TYPE_SOCKET);
			}
			rbio = SSL_get_rbio(ctx->vdc_ssl);
			if (rbio) {
				rbio = BIO_find_type(rbio, BIO_TYPE_SOCKET);
			}
		} else {
			wbio = NULL;
			rbio = NULL;
		}
		pfd->events = 0;
		if (wbio && BIO_should_retry(wbio)) {
			if (BIO_should_read(wbio))
				pfd->events |= POLLIN;
			if (BIO_should_write(wbio))
				pfd->events |= POLLOUT;
		}
		if (rbio && BIO_should_retry(rbio)) {
			if (BIO_should_read(rbio))
				pfd->events |= POLLIN;
			if (BIO_should_write(rbio))
				pfd->events |= POLLOUT;
		}
		return 0;
	case VCDD_STATE_ESTABLISHED:
	case VCDD_STATE_LISTEN:
		/*		pfd->events |= POLLIN|POLLOUT; ???? */
		return 0;
	}
}

static int
vcd_tls_poll_dispatch(void *vc, struct pollfd *pfd)
{
	vcd_tls_ctx_t *ctx;
	int rval;
	
	if (!vc || !pfd) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
		return 0;
	case VCDD_STATE_SHUTDOWN:
		return 0;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
		if ((pfd->events & (POLLIN|POLLOUT)) == 0) {
			/* not yet connected */
			return 0;
		}

		/* Set up SSL context */
		if (ctx->vdc_ssl_ctx == NULL) {
			rval = vcd_tls_sslctx_init(ctx);
			if (rval != EOK) {
				return rval;
			}
		}
		if ((rval = vcd_tls_do_handshake(ctx, 
						 TLS_CONN_CLIENT)) != EOK) {
			return rval;
		}
		return 0;
	case VCDD_STATE_SSL_HANDSHAKE:
		/* check if handshake is done */
		if ((rval = vcd_tls_do_handshake(ctx, 
						 TLS_CONN_CLIENT)) != EOK) {
			return rval;
		}

		return 0;
	case VCDD_STATE_ESTABLISHED:
	case VCDD_STATE_LISTEN:
		return 0;
	default:
		return ENOTCONN;
	}
}

static int
vcd_tls_getfd(void *vc, int *fdp)
{
	vcd_tls_ctx_t *ctx;
	
	if (!vc || !fdp) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	switch (ctx->vdc_state) {
	case VCDD_STATE_SHUTDOWN:
	case VCDD_STATE_CONNECTING:
	case VCDD_STATE_ESTABLISHED:
	case VCDD_STATE_LISTEN:
	case VCDD_STATE_SSL_HANDSHAKE:
		*fdp = ctx->vdc_fd;
		return 0;
	case VCDD_STATE_CLOSED:
	default:
		return ENOTCONN;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	}
}

static int
vcd_tls_fromfd(ar_svc_attr_t *svc_attr, int fd, void **vcp)
{
	vcd_tls_ctx_t *ctx;
	struct sockaddr_storage ss;
	socklen_t len;
	void *vc;
	int flags;
	int err;

	/* FIXME: is there a way to check if this is SOCK_STREAM?
	 * we rely on the remote addr to determine if the socket is a
	 * listener or not.  That is not entirely foolproof either.
	 */

	/* make sure it's in non-block mode */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return errno;
	}
	flags |= O_NONBLOCK|O_NDELAY;
	err = fcntl(fd, F_SETFL, flags);
	if (err != 0) {
		return errno;
	}

	/* close on exec */
	err = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (err != 0) {
		return errno;
	}

	err = vcd_tls_init(NULL, svc_attr, &vc);
	if (err != EOK) {
		return err;
	}
	ctx = (vcd_tls_ctx_t *)vc;

	len = sizeof(ss);
	err = getpeername(fd, (struct sockaddr *)&ss, &len);
	if (err == 0) {
		/* TCP is connected, but TLS handshaking is not done yet,
		 * so still make it in connecting state
		 */
		ctx->vdc_state = VCDD_STATE_CONNECTING;
	} else {
		ctx->vdc_state = VCDD_STATE_LISTEN;
	}

	ctx->vdc_fd = fd;
	ctx->vdc_bufcnt = 0;

	*vcp = vc;
	return 0;
}

static int
vcd_tls_conn(void *vc, const arpc_addr_t *na, arpc_createerr_t *errp)
{
	vcd_tls_ctx_t *ctx;
	struct sockaddr *sa;
	int flags;
	int ret;

#if 0
	int err;
	char errbuf[256];
#endif

	if (!vc || !na) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	if (na->len < sizeof(*sa)) {
		return EINVAL;
	}
	sa = (struct sockaddr *)na->buf;
	switch (sa->sa_family) {
	case AF_INET:
		if (na->len < sizeof(struct sockaddr_in)) {
			return EINVAL;
		}
		break;
	case AF_INET6:
		if (na->len < sizeof(struct sockaddr_in6)) {
			return EINVAL;
		}
		break;
	case AF_LOCAL:
		if (na->len < sizeof(struct sockaddr_un)) {
			return EINVAL;
		}
		break;
	default:
		return  EINVAL;
	}

	switch (ctx->vdc_state) {
	case VCDD_STATE_CLOSED:
		ret = socket(sa->sa_family, SOCK_STREAM, 0);
		if (ret < 0) {
			ctx->vdc_state = VCDD_STATE_ERROR;
			ctx->vdc_err = errno;
			return errno;
		}
		ctx->vdc_fd = ret;

		/* nonblock */
		flags = fcntl(ctx->vdc_fd, F_GETFL, 0);
		if (flags == -1) {
			ret = errno;
			goto error;
		}
		flags |= O_NONBLOCK|O_NDELAY;
		ret = fcntl(ctx->vdc_fd, F_SETFL, flags);
		if (ret != 0) {
			ret = errno;
			goto error;
		}

		/* close on exec */
		ret = fcntl(ctx->vdc_fd, F_SETFD, FD_CLOEXEC);
		if (ret != 0) {
			ret = errno;
			goto error;
		}

		ret = connect(ctx->vdc_fd, sa, na->len);
		if (ret < 0) {
			ret = errno;
			if (ret != EINPROGRESS) {
				goto error;
			}
			ctx->vdc_state = VCDD_STATE_CONNECTING;
		} else {
			/* Shouldn't reach here since fd is non-blocking.
			 * Just temporarily set the state to be ESTABLISHED
			 */
			ctx->vdc_state = VCDD_STATE_ESTABLISHED;
		}

		if (ctx->vdc_state == VCDD_STATE_CONNECTING) {
			/* wait for connection to complete */
			return EOK;
		}
		return 0;
	case VCDD_STATE_ERROR:
		return ctx->vdc_err;
	case VCDD_STATE_CONNECTING:
	case VCDD_STATE_SHUTDOWN:
	case VCDD_STATE_ESTABLISHED:
		return EBUSY;
	default:
		return EINVAL;
	}

 error:
	close(ctx->vdc_fd);
	ctx->vdc_fd = -1;
	ctx->vdc_err = ret;
	ctx->vdc_state = VCDD_STATE_ERROR;
	return ret;
}

static int
vcd_get_ssl_error(char *errbuf, size_t errlen)
{
	char *fatal;
	int off;
	int errqueue;
	int errnum;
	int lib;
	int func;

	fatal = NULL;
	off = 0;
	errqueue = 0;
	memset(errbuf, 0, errlen); 
 
	/* ERR_get_error() returns the earliest error in queue */
	errqueue = ERR_get_error();
	while (errqueue != 0) {
		lib = ERR_GET_LIB(errqueue);
		func = ERR_GET_FUNC(errqueue);
		errnum = ERR_GET_REASON(errqueue);
		if (ERR_FATAL_ERROR(errqueue)) {
			fatal = " fatal";
		} else {
			fatal = "";
		}
 
		if (errqueue == ERR_PACK(ERR_R_SSL_LIB, 
					 SSL_F_SSL3_GET_SERVER_CERTIFICATE,
					 SSL_R_CERTIFICATE_VERIFY_FAILED)) {
			snprintf(&errbuf[off], errlen - off,
				 "unable to verify server certificate");
		} else if (lib == ERR_LIB_SSL) {
			snprintf(&errbuf[off], errlen - off, 
				 "error %d in function %d%s", 
				 errnum, func, fatal);
		} else {
			snprintf(&errbuf[off], errlen - off, 
				 "OpenSSL error: %d, func %d, "
				 "lib %d%s", errnum, func, lib, fatal);
		}
		off = strlen(errbuf);
		errqueue = ERR_get_error();
		if (errqueue != 0) {
			snprintf(&errbuf[off], errlen - off, " ");
			off = strlen(errbuf);
		}
	}
	/* don't care SSL internal error code, just return EPROTO */ 
	return EPROTO;
}

static int
vcd_get_ssl_io_error(vcd_tls_ctx_t *ctx, int ret, char *errbuf, size_t errlen)
{
	int err;
	int off = 0;
	int errqueue = 0;
	int errcode = 0;

	/* save the errno before it potentially gets trashed */
	err = errno;

	memset(errbuf, 0, errlen); 

	errcode = SSL_get_error(ctx->vdc_ssl, ret);
	switch (errcode) { 
	case SSL_ERROR_NONE:
		if (ret < 0) {
			/* err set above */
			if (err != EOK) {
				err = EPROTO;
			}
			snprintf(errbuf, errlen, "ssl socket error: %s",
				 strerror(err));
			return err;
		} else {
			return EOK;
		}
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_CONNECT:
		snprintf(errbuf, errlen, "try again later");
		return EAGAIN;
	case SSL_ERROR_SSL:
		snprintf(errbuf, errlen, "ssl err: ");
		off = strlen(errbuf);
		err = EIO;
		break;
	case SSL_ERROR_SYSCALL:
		snprintf(errbuf, errlen, "ssl syscall err: ");
		off = strlen(errbuf);
		errqueue = ERR_peek_error();
		if (errqueue != 0) {
			err = EPROTO;
			break;
		}
		if (ret == 0) {
			/* special case: */
			snprintf(errbuf, errlen, "connection closed by "
				 "other side");
			err = EPROTO;
		} else if (ret < 0) {
			/* err set to errno above */
			if (err == EOK) {
				err = EPROTO;
			}
			if (err == EPIPE) {
				snprintf(errbuf, errlen, "connection closed "
					 "by other side");
			} else {
				snprintf(&errbuf[off], errlen - off, "%s",
					 strerror(err));
			}
		} else {
			snprintf(&errbuf[off], errlen - off, "ret %d", ret);
			err = EPROTO;
		}
		off = strlen(errbuf);
		break;
	case SSL_ERROR_ZERO_RETURN:
		return EOK;

	default:
		snprintf(errbuf, errlen, "unexpected ssl error: %d", errcode);
		off = strlen(errbuf);
		err = EIO;
		break;
	}

	/* get the error stack */
	if (errlen > off) {
		vcd_get_ssl_error(&errbuf[off], errlen - off);
	}
	return err;
}

static int
vcd_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	vcd_tls_ctx_t *ctx;
	SSL *ssl;

	ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
					 SSL_get_ex_data_X509_STORE_CTX_idx());
	if (!ssl) {
		/* should not be possible */
		return 0;
	}

	ctx = (vcd_tls_ctx_t *)SSL_get_app_data(ssl);
	if (ctx->vdc_tls_verify) {
		return (ctx->vdc_tls_verify)(ctx->vdc_tls_arg,
					     preverify_ok, x509_ctx);
	} else {
		return preverify_ok;
	}
}


static void
vcd_info_cb(const SSL *ssl, int where, int ret)
{
	vcd_tls_ctx_t *ctx;

	ctx = (vcd_tls_ctx_t *)SSL_get_app_data(ssl);
	if (ctx->vdc_tls_info) {
		(*ctx->vdc_tls_info)(ctx->vdc_tls_arg, ssl, where, ret);
	}
}

static int
vcd_base_verify(X509_STORE_CTX *ctx, void *arg)
{
	X509_VERIFY_PARAM *param;

	/* for now we have to accept any purpose because lightspeed 
	 * certs only have a 'client auth' and 'eapol' purposes.
	 */
	param = X509_STORE_CTX_get0_param(ctx);
	if (param) {
		X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_ANY);
	}

	/* now do the standard verifier */
	return X509_verify_cert(ctx);
}

static int
vcd_tls_sslctx_init(vcd_tls_ctx_t *ctx)
{
	SSL_CTX *sslctx = NULL;
	EVP_PKEY *pkey;
	X509 *cert;
	STACK_OF(X509) *certs;
	bool_t do_verify;
	int err;
	char errbuf[256];

	if (!(sslctx = SSL_CTX_new(TLSv1_method()))) {
		err = vcd_get_ssl_error(errbuf, sizeof(errbuf));
		fprintf (stderr, "SSL_CTX_new: %s\n", errbuf);
		return err;
	}

	SSL_CTX_set_info_callback(sslctx, &vcd_info_cb);
	SSL_CTX_set_options(sslctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|
			    SSL_OP_NO_SSLv3);
	SSL_CTX_set_mode(sslctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_mode(sslctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_mode(sslctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	/* try to drain the data from kernel as fast as possible */
	SSL_CTX_set_read_ahead(sslctx, 1);

	if (!SSL_CTX_set_cipher_list(sslctx, "ALL:!ADH:!EXP:!LOW:"
				     "!SSLv2:!IDEA")) {
		SSL_CTX_free(sslctx);
		err = vcd_get_ssl_error(errbuf, sizeof(errbuf));
		fprintf (stderr, "SSL_CTX_set_cipher_list: %s\n", errbuf);
		return err;
	}

	if (ctx->vdc_tls_setup) {
		err = (*ctx->vdc_tls_setup)(ctx->vdc_tls_arg, 
					    sslctx, &do_verify);
		if (err != EOK) {
			SSL_CTX_free(sslctx);
			return err;
		}
	} else {
		do_verify = FALSE;
	}

	/* HACK: because of the way SSL applies defaults, 
	 * SSL_CTX_set_purpose(sslctx, X509_PURPOSE_ANY) &
	 * SSL_set_purpose(ctx->vdc_ssl, X509_PURPOSE_ANY);
	 * are pontless for allowing a non SSL puropse cert to work
	 * for TLS (another HACK to work around the fact that we need to
	 * use lightspeed certs for this purpose under some cases.
	 * Anyway, the only window we get is if we instll a cert verify
	 * hook, modify the context in the callback, then call the standard
	 * verifyier... It sucks...
	 */

	SSL_CTX_set_cert_verify_callback(sslctx, vcd_base_verify, NULL);

	if (do_verify) {
		SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER|
				   SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
				   &vcd_verify_cb);
	} else {
		SSL_CTX_set_verify(sslctx, SSL_VERIFY_NONE, NULL);
	}

	/* Parse PKCS12 object to get key and cert */
	if (ctx->vdc_pkcs12) {
		pkey = NULL;
		cert = NULL;
		certs = NULL;
		err = EOK;
		if (!PKCS12_parse(ctx->vdc_pkcs12, ctx->vdc_passwd,
				  &pkey, &cert, &certs)) {
			SSL_CTX_free(sslctx);
			fprintf(stderr, "Failed to parse PKCS12 object\n");
			return EPROTO;
		}
		if (cert) {
			if (SSL_CTX_use_certificate(sslctx, cert) != 1)
				err = -1;
			X509_free(cert);
		}
		if (err != EOK) {
			SSL_CTX_free(sslctx);
			return err;
		}
		if (pkey) {
			if (SSL_CTX_use_PrivateKey(sslctx, pkey) != 1)
				err = -1;
			EVP_PKEY_free(pkey);
		}
		if (err != EOK) {
			SSL_CTX_free(sslctx);
			err = vcd_get_ssl_error(errbuf, sizeof(errbuf));
			fprintf (stderr, "SSL_CTX_use_PrivateKey: %s\n", 
				 errbuf);
			return err;
		}
		if (certs) {
			while ((cert = sk_X509_pop(certs)) != NULL) {
				X509_NAME_oneline(X509_get_subject_name(cert),
						  errbuf, sizeof(errbuf));
				if (SSL_CTX_add_extra_chain_cert(sslctx, 
								 cert) != 1) {
					err = -1;
					break;
				}
			}
			sk_X509_free(certs);
		}
		if (err != EOK) {
			SSL_CTX_free(sslctx);
			err = vcd_get_ssl_error(errbuf, sizeof(errbuf));
			fprintf(stderr, "SSL_CTX_add_extra_chain_cert: %s\n", 
				errbuf);
			return err;
		}
	}

	ctx->vdc_ssl_ctx = sslctx;
	return EOK;
}

/* Call Sequence (FIXME):
 *   vcd_tls_do_handshake() can be called in the following situations:
 *   (1) from vcd_tls_poll_dispatch, client receives SYN+ACK from server
 *	=> This happens when vcd_tls_conn returns EOK but connect
 *		returns -1 in vcd_tls_conn due to non-blocking. In this case,
 *		ctx->state=VCDD_STATE_CONNECTING, and ctx->vdc_ssl has not
 *		been allocated yet (CLIENT MODE). This is the normal case
 *		when a client connection is set up.
 *   (2) from vcd_tls_poll_dispatch, an earlier vcd_tls_do_handshake call
 *	failed
 *	=> This happens when an earlier vcd_tls_do_handshake failed for
 *		some reason. In this case, ctx->state=VCDD_STATE_SSL_HANDSHAKE,
 *		and ctx->vdc_ssl has been allocated (either CLIENT or SERVER)
 *   (2) from vcd_tls_accept
 *	=> In this case, ctx->state=VCDD_STATE_SSL_HANDSHAKE, ctx->vdc_ssl
 *		has not been created yet (SERVER MODE)
 */
static int
vcd_tls_do_handshake(vcd_tls_ctx_t *ctx, tls_conn_mode_t mode)
{
	int err;
	char errbuf[256];

	if (!ctx)
		return EINVAL;

	if (ctx->vdc_state != VCDD_STATE_CONNECTING &&
	    ctx->vdc_state != VCDD_STATE_SSL_HANDSHAKE)
		return EINVAL;

	if (!ctx->vdc_ssl) {
		ctx->vdc_ssl = SSL_new(ctx->vdc_ssl_ctx);
		if (!ctx->vdc_ssl) {
			err = vcd_get_ssl_error(errbuf, sizeof(errbuf));
			fprintf (stderr, "SSL_new: %s\n", errbuf);
			return err;
		}
		SSL_set_app_data(ctx->vdc_ssl, ctx);

		if (!SSL_set_session(ctx->vdc_ssl, NULL)) {
			SSL_free(ctx->vdc_ssl);
			ctx->vdc_ssl = NULL;
			err = vcd_get_ssl_error(errbuf, sizeof(errbuf));
			fprintf (stderr, "SSL_set_session: %s\n", errbuf);
			return err;
		}
		
		if (!SSL_clear(ctx->vdc_ssl)) {
			SSL_free(ctx->vdc_ssl);
			ctx->vdc_ssl = NULL;
			err = vcd_get_ssl_error(errbuf, sizeof(errbuf));
			fprintf (stderr, "SSL_clear: %s\n", errbuf);
			return err;		
		}
		SSL_set_fd(ctx->vdc_ssl, ctx->vdc_fd);
		
		switch (mode) {
		case TLS_CONN_CLIENT:
			SSL_set_connect_state(ctx->vdc_ssl);
			break;
		case TLS_CONN_SERVER:
			SSL_set_accept_state(ctx->vdc_ssl);
			break;
		}
	}
	
	assert(ctx->vdc_ssl != NULL);
	assert(ctx->vdc_ssl_ctx != NULL);
	assert(ctx->vdc_fd != 0);
	
	if ((err = SSL_do_handshake(ctx->vdc_ssl)) != 1) {
		if (err != EOK && err != EAGAIN) {
			err = vcd_get_ssl_io_error(ctx, err, 
						   errbuf, sizeof(errbuf));
			if (err == EAGAIN) {
				ctx->vdc_state = VCDD_STATE_SSL_HANDSHAKE;
				return EOK;
			}
			SSL_free(ctx->vdc_ssl);
			ctx->vdc_ssl = NULL;
			return err;
		} else if (err == EAGAIN) {
			ctx->vdc_state = VCDD_STATE_SSL_HANDSHAKE;
			return EOK;
		}
	}
	ctx->vdc_state = VCDD_STATE_ESTABLISHED;
	return EOK;
}

static int
vcd_tls_sslctx_free(vcd_tls_ctx_t *ctx)
{
	if (ctx == NULL || ctx->vdc_ssl_ctx == NULL) {
		return EINVAL;
	}

	ctx->vdc_tls_setup = NULL;
	ctx->vdc_tls_verify = NULL;
	ctx->vdc_tls_info = NULL;
	ctx->vdc_tls_arg = NULL;

	/* Not sure if this is correct */
	if (ctx->vdc_ssl_ctx->extra_certs != NULL) {
		sk_X509_pop_free(ctx->vdc_ssl_ctx->extra_certs, X509_free);
		ctx->vdc_ssl_ctx->extra_certs = NULL;
	}
	/*	SSL_set_quiet_shutdown(ctx->vdc_ssl, 1);
	  SSL_shutdown(ctx->vdc_ssl);*/
	if (ctx->vdc_ssl) {
		SSL_free(ctx->vdc_ssl);
		ctx->vdc_ssl = NULL;
	}
	if (ctx->vdc_ssl_ctx) {
		SSL_CTX_free(ctx->vdc_ssl_ctx);
		ctx->vdc_ssl_ctx = NULL;
	}
	return EOK;
}

static int
vcd_tls_accept(void *vc, void **vcpp)
{
	vcd_tls_ctx_t *ctx1;
	vcd_tls_ctx_t *ctx2;
	struct sockaddr_storage sa;
	socklen_t len;
	int flags;
	int fd;
	int ret;

	if (!vc || !vcpp) {
		return EINVAL;
	}

	ctx1 = (vcd_tls_ctx_t *)vc;

	switch (ctx1->vdc_state) {
	case VCDD_STATE_LISTEN:
		break;
	case VCDD_STATE_ERROR:
		return ctx1->vdc_err;
	default:
		return EINVAL;
	}

	memset(&sa, 0, sizeof(sa));
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
	sa.ss_len = sizeof(sa);
#endif

	len = sizeof(sa);
	ret = accept(ctx1->vdc_fd, (struct sockaddr *)&sa, &len);
	if (ret < 0) {
		*vcpp = NULL;
		return errno;
	}
	fd = ret;

	/* switch it to non-blocking */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		ret = errno;
		close(fd);
		return ret;
	}
	flags |= O_NONBLOCK|O_NDELAY;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret != 0) {
		ret = errno;
		close(fd);
		return ret;
	}

	/* close on exec */
	ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (ret != 0) {
		ret = errno;
		close(fd);
		return ret;
	}

	ctx2 = (vcd_tls_ctx_t *)malloc(sizeof(*ctx1));
	if (!ctx2) {
		close(fd);
		return ENOMEM;
	}

	/* Copy everything include PKCS12*, SSL*, and SSL_CTX*.
	 * These pointers should be assgined new values
	 */
	memcpy(ctx2, ctx1, sizeof(*ctx2));
	ctx2->vdc_fd = fd;
	ctx2->vdc_ssl = NULL;
	ctx2->vdc_ssl_ctx = NULL;
	ctx2->vdc_passwd = NULL;
	ret = vcd_pkcs12_duplicate(ctx1->vdc_pkcs12, &ctx2->vdc_pkcs12);
	if (ret != EOK) {
		vcd_tls_destroy(ctx2);
		return ret;
	}

	if (ctx1->vdc_passwd) {
		ctx2->vdc_passwd = strdup(ctx1->vdc_passwd);
		if (!ctx2->vdc_passwd) {
			vcd_tls_destroy(ctx2);
			return ENOMEM;
		}
	}

	/* Set up SSL context */
	ret = vcd_tls_sslctx_init(ctx2);
	if (ret != EOK) {
		vcd_tls_destroy(ctx2);
		return ret;
	}
	ctx2->vdc_state = VCDD_STATE_SSL_HANDSHAKE;
	ctx2->vdc_fd = fd;

 	ret = vcd_tls_do_handshake(ctx2, TLS_CONN_SERVER);
	if (ret != EOK) {
		vcd_tls_destroy(ctx2);
		return ret;
	}

	if (ctx2->vdc_state != VCDD_STATE_SSL_HANDSHAKE)
		ctx2->vdc_state = VCDD_STATE_ESTABLISHED;

	*vcpp = ctx2;
	return 0;
}

static int
vcd_tls_getladdr(void *vc, arpc_addr_t *nb)
{
	vcd_tls_ctx_t *ctx;
	struct sockaddr_storage ss;
	socklen_t slen;
	int err;
	
	if (!vc || !nb) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	memset(&ss, 0, sizeof(ss));
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
	ss.ss_len = sizeof(ss);
#endif
	slen = sizeof(ss);
	err = getsockname(ctx->vdc_fd, (struct sockaddr *)&ss, &slen);
	if (err < 0) {
		err = errno;
		return err;
	}

	nb->buf = malloc(slen);
	if (!nb->buf) {
		return ENOMEM;
	}
	memcpy(nb->buf, &ss, slen);
	nb->len = slen;
	nb->maxlen = slen;
	return 0;
}

static int
vcd_tls_getfamily(void *vc, sa_family_t *famp)
{
	vcd_tls_ctx_t *ctx;
	struct sockaddr_storage ss;
	socklen_t slen;
	int err;
	
	if (!vc || !famp) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	memset(&ss, 0, sizeof(ss));
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
	ss.ss_len = sizeof(ss);
#endif
	slen = sizeof(ss);
	err = getsockname(ctx->vdc_fd, (struct sockaddr *)&ss, &slen);
	if (err < 0) {
		err = errno;
		return err;
	}
	*famp = ss.ss_family;
	return 0;
}

static int
vcd_tls_islistener(void *vc, bool_t *listenp)
{
	vcd_tls_ctx_t *ctx;

	if (!vc || !listenp) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	if (ctx->vdc_state == VCDD_STATE_LISTEN) {
		*listenp = TRUE;
	} else {
		*listenp = FALSE;
	}
	return 0;
}

static int
vcd_tls_listen(void *vc, const arpc_addr_t *addr)
{
	vcd_tls_ctx_t *ctx;
	struct sockaddr *sa;
	int flags;
	int err;
	int fd;
	
	if (!vc || !addr) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	if (ctx->vdc_fd >= 0 || ctx->vdc_state != VCDD_STATE_CLOSED) {
		return EBUSY;
	}

	if (addr->len < sizeof(*sa)) {
		return EINVAL;
	}
	sa = (struct sockaddr *)addr->buf;
	switch (sa->sa_family) {
	case AF_INET:
		if (addr->len < sizeof(struct sockaddr_in)) {
			return EINVAL;
		}
		break;
	case AF_INET6:
		if (addr->len < sizeof(struct sockaddr_in6)) {
			return EINVAL;
		}
		break;
	case AF_LOCAL:
		if (addr->len < sizeof(struct sockaddr_un)) {
			return EINVAL;
		}
		break;
	default:
		return EINVAL;
	}

	fd = socket(sa->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		return errno;
	}

	/* nonblock */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		err = errno;
		close(fd);
		return err;
	}
	flags |= O_NONBLOCK|O_NDELAY;
	err = fcntl(fd, F_SETFL, flags);
	if (err != 0) {
		err = errno;
		close(fd);
		return err;
	}

	err = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (err != 0) {
		err = errno;
		close(fd);
		return err;
	}

	err = bind(fd, (struct sockaddr *)addr->buf, addr->len);
	if (err != 0) {
		err = errno;
		close(fd);
		return err;
	}

	err = listen(fd, 5);
	if (err != 0) {
		err = errno;
		close(fd);
		return err;
	}

	ctx->vdc_fd = fd;
	ctx->vdc_state = VCDD_STATE_LISTEN;

	return 0;
}


static int
vcd_tls_init(ar_clnt_attr_t *clnt_attr, ar_svc_attr_t *svc_attr, void **vcpp)
{
	vcd_tls_ctx_t *ctx = NULL;
	const char *passwd;
	uint8_t *buf;
	uint32_t len;
	PKCS12 *p12 = NULL;
	BIO *bio = NULL;

	/* clnt_attr and svc_attr: if and only if one of them is Non-NULL */
	if (!vcpp || (clnt_attr && svc_attr) || (!clnt_attr && !svc_attr)) {
		return EINVAL;
	}
	
	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		return ENOMEM;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->vdc_state = VCDD_STATE_CLOSED;
	ctx->vdc_fd = -1;
	ctx->vdc_bufcnt = 0;
	ctx->vdc_events = 0;

	if (clnt_attr) {
		buf = clnt_attr->ca_pkcs12;
		len = clnt_attr->ca_pkcs12_len;
		passwd = clnt_attr->ca_pkcs12_passwd;
		ctx->vdc_tls_setup = clnt_attr->ca_tls_setup_cb;
		ctx->vdc_tls_arg = clnt_attr->ca_tls_arg;
		ctx->vdc_tls_verify = clnt_attr->ca_tls_verify_cb;
		ctx->vdc_tls_info = clnt_attr->ca_tls_info_cb;
	} else {
		buf = svc_attr->sa_pkcs12;
		len = svc_attr->sa_pkcs12_len;
		passwd = svc_attr->sa_pkcs12_passwd;
		ctx->vdc_tls_setup = svc_attr->sa_tls_setup_cb;
		ctx->vdc_tls_arg = svc_attr->sa_tls_arg;
		ctx->vdc_tls_verify = svc_attr->sa_tls_verify_cb;
		ctx->vdc_tls_info = svc_attr->sa_tls_info_cb;
		if (tspecisset(&svc_attr->sa_create_tmout)) {
			memcpy(&ctx->vdc_tls_timeout, &svc_attr->sa_create_tmout,
			       sizeof(struct timespec));
		}
	}

	if (passwd) {
		ctx->vdc_passwd = strdup(passwd);
		if (!ctx->vdc_passwd) {
			free(ctx);
			return ENOMEM;
		}
	}


	if (buf) {
		bio = BIO_new_mem_buf(buf, len);
		if (!bio) {
			if (ctx->vdc_passwd) {
				free(ctx->vdc_passwd);
				ctx->vdc_passwd = NULL;
			}
			free(ctx);
			return ENOMEM;
		}

		p12 = d2i_PKCS12_bio(bio, NULL);
		BIO_free(bio);
		if (!p12) {
			if (ctx->vdc_passwd) {
				free(ctx->vdc_passwd);
				ctx->vdc_passwd = NULL;
			}
			free(ctx);
			return EPARSE;
		}
		
		ctx->vdc_pkcs12 = p12;
	}

	*vcpp = ctx;
	return 0;
}

static int
vcd_pkcs12_duplicate(PKCS12 *p12, PKCS12 **retp)
{
	BIO *bio = NULL;
	PKCS12 *val;
	int len;

	if (!p12 || !retp) {
		return EINVAL;
	}

	bio = BIO_new(BIO_s_mem());
	if (!bio) {
		return ENOMEM;
	}

	len = i2d_PKCS12_bio(bio, p12);
	if (len <= 0) {
		/* error case */
		BIO_free(bio);
		return EPROTO;
	}

	/* consume it all out */
	val = d2i_PKCS12_bio(bio, NULL);
	BIO_free(bio);
	if (!val) {
		return EPROTO;
	}

	*retp = val;
	return EOK;
}

static int
vcd_tls_destroy(void *vcp)
{
	vcd_tls_ctx_t *ctx;
	
	if (!vcp) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vcp;

	if (ctx->vdc_fd >= 0) {
		close(ctx->vdc_fd);
		ctx->vdc_fd = -1;
	}

	if (ctx->vdc_pkcs12) {
		PKCS12_free(ctx->vdc_pkcs12);
		ctx->vdc_pkcs12 = NULL;
	}
	if (ctx->vdc_passwd) {
		free(ctx->vdc_passwd);
		ctx->vdc_passwd = NULL;
	}
	vcd_tls_sslctx_free(ctx);
	free(ctx);
	return 0;
}

static int
vcd_tls_get_timeout(void *vc, struct timespec *tmout)
{
	vcd_tls_ctx_t *ctx;
	
	if (!vc || !tmout) {
		return EINVAL;
	}

	ctx = (vcd_tls_ctx_t *)vc;

	memcpy(tmout, &ctx->vdc_tls_timeout, sizeof(*tmout));
	return 0;
}

int 
ar_vcd_tls(ar_vcd_t *drv)
{
	if (!drv) {
		return EINVAL;
	}

	*drv = &vcd_tls;
	return 0;
}
