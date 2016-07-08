/*
 * Copyright (c) 2011  Charles Hardin <ckhardin@gmail.com>
 * All Rights Reserved
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
 * auth_unix.c, Implements UNIX style authentication parameters.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * The system is very weak.  The client uses no encryption for it's
 * credentials and only sends null verifiers.  The server sends backs
 * null verifiers or optionally a verifier that suggests a new short hand
 * for the credentials.
 *
 */

#include "compat.h"

#include "namespace.h"
#include "reentrant.h"
#include <sys/cdefs.h>
#include <sys/param.h>

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <libarpc/types.h>
#include <libarpc/axdr.h>
#include <libarpc/arpc.h>
#include <libarpc/auth.h>
#include <libarpc/auth_unix.h>
#include "un-namespace.h"

/* auth_unix.c */
static void authunix_nextverf(ar_auth_t *);
static int authunix_marshal(ar_auth_t *, arpc_msg_t *);
static int authunix_cleanup(ar_auth_t *, arpc_msg_t *);
static int authunix_validate(ar_auth_t *, ar_opaque_auth_t *);
static int authunix_refresh(ar_auth_t *, void *);
static void authunix_destroy(ar_auth_t *);
static void marshal_new_auth(ar_auth_t *);

/*
 * This struct is pointed to by the ah_private field of an auth_handle.
 */
struct audata {
	ar_opaque_auth_t	au_origcred;	/* original credentials */
	ar_opaque_auth_t	au_shcred;	/* short hand cred */
	u_long			au_shfaults;	/* short hand cache faults */
	char			au_marshed[AR_MAX_AUTH_BYTES];
	u_int			au_mpos;	/* xdr pos at end of marshed */
};
#define	AUTH_PRIVATE(auth)	((struct audata *)auth->ah_private)

static ar_auth_ops_t authunix_ops = {
	&authunix_nextverf,
	&authunix_marshal,
	&authunix_cleanup,
	&authunix_validate,
	&authunix_refresh,
	&authunix_destroy
};

/*
 * Create a unix style authenticator.
 * Returns an auth handle with the given stuff in it.
 */
ar_auth_t *
authunix_create(char *machname, int uid, int gid, int len, int *aup_gids)
{
	ar_authunix_parms_t aup;
	char mymem[AR_MAX_AUTH_BYTES];
	struct timeval now;
	axdr_state_t xdrs;
	ar_auth_t *auth;
	struct audata *au;

	/*
	 * Allocate and set up auth handle
	 */
	au = NULL;
	auth = mem_alloc(sizeof(*auth));
#ifndef _KERNEL
	if (auth == NULL) {
		warnx("authunix_create: out of memory");
		goto cleanup_authunix_create;
	}
#endif
	au = mem_alloc(sizeof(*au));
#ifndef _KERNEL
	if (au == NULL) {
		warnx("authunix_create: out of memory");
		goto cleanup_authunix_create;
	}
#endif
	auth->ah_ops = &authunix_ops;
	auth->ah_private = (caddr_t)au;
	auth->ah_verf = au->au_shcred = ar_null_auth;
	au->au_shfaults = 0;
	au->au_origcred.oa_base = NULL;

	/*
	 * fill in param struct from the given params
	 */
	(void)gettimeofday(&now, NULL);
	aup.aup_time = now.tv_sec;
	aup.aup_machname = machname;
	aup.aup_uid = uid;
	aup.aup_gid = gid;
	aup.aup_len = (u_int)len;
	aup.aup_gids = aup_gids;

	/*
	 * Serialize the parameters into origcred
	 */
	axdrmem_create(&xdrs, mymem, AR_MAX_AUTH_BYTES, AXDR_ENCODE);
	if (! xdr_authunix_parms(&xdrs, &aup)) 
		abort();
	au->au_origcred.oa_length = len = axdr_getpos(&xdrs);
	au->au_origcred.oa_flavor = AR_AUTH_UNIX;
#ifdef _KERNEL
	au->au_origcred.oa_base = mem_alloc((u_int) len);
#else
	if ((au->au_origcred.oa_base = mem_alloc((u_int) len)) == NULL) {
		warnx("authunix_create: out of memory");
		goto cleanup_authunix_create;
	}
#endif
	memmove(au->au_origcred.oa_base, mymem, (size_t)len);

	/*
	 * set auth handle to reflect new cred.
	 */
	auth->ah_cred = au->au_origcred;
	marshal_new_auth(auth);
	return (auth);
#ifndef _KERNEL
 cleanup_authunix_create:
	if (auth)
		mem_free(auth, sizeof(*auth));
	if (au) {
		if (au->au_origcred.oa_base)
			mem_free(au->au_origcred.oa_base, (u_int)len);
		mem_free(au, sizeof(*au));
	}
	return (NULL);
#endif
}

/*
 * Returns an auth handle with parameters determined by doing lots of
 * syscalls.
 */
ar_auth_t *
authunix_create_default(void)
{
	int len;
	char machname[MAXHOSTNAMELEN + 1];
	uid_t uid;
	gid_t gid;
	gid_t gids[NGRPS];

	if (gethostname(machname, sizeof machname) == -1)
		abort();
	machname[sizeof(machname) - 1] = 0;
	uid = geteuid();
	gid = getegid();
	if ((len = getgroups(NGRPS, gids)) < 0)
		abort();
	/* XXX: interface problem; those should all have been unsigned */
	return (authunix_create(machname, (int)uid, (int)gid, len,
	    (int *)gids));
}

/*
 * authunix operations
 */

/* ARGSUSED */
static void
authunix_nextverf(ar_auth_t *auth)
{
	/* no action necessary */
}

static int
authunix_marshal(ar_auth_t *auth, arpc_msg_t *msg)
{
	struct audata *au;

	assert(auth != NULL);
	assert(msg != NULL);

	au = AUTH_PRIVATE(auth);
	msg->arm_call.acb_cred = auth->ah_cred;
	msg->arm_call.acb_verf = auth->ah_verf;
	return TRUE;
}

static int
authunix_cleanup(ar_auth_t *auth, arpc_msg_t *msg)
{
	msg->arm_call.acb_cred = ar_null_auth;
	msg->arm_call.acb_verf = ar_null_auth;
	return 0;
}

static bool_t
authunix_validate(ar_auth_t *auth, ar_opaque_auth_t *verf)
{
	struct audata *au;
	axdr_state_t xdrs;

	assert(auth != NULL);
	assert(verf != NULL);

	if (verf->oa_flavor == AR_AUTH_SHORT) {
		au = AUTH_PRIVATE(auth);
		axdrmem_create(&xdrs, verf->oa_base, verf->oa_length,
		    AXDR_DECODE);

		if (au->au_shcred.oa_base != NULL) {
			mem_free(au->au_shcred.oa_base,
			    au->au_shcred.oa_length);
			au->au_shcred.oa_base = NULL;
		}
		if (axdr_opaque_auth(&xdrs, &au->au_shcred)) {
			auth->ah_cred = au->au_shcred;
		} else {
			xdrs.x_op = AXDR_FREE;
			(void)axdr_opaque_auth(&xdrs, &au->au_shcred);
			au->au_shcred.oa_base = NULL;
			auth->ah_cred = au->au_origcred;
		}
		marshal_new_auth(auth);
	}
	return (TRUE);
}

static bool_t
authunix_refresh(ar_auth_t *auth, void *dummy)
{
	struct audata *au = AUTH_PRIVATE(auth);
	ar_authunix_parms_t aup;
	struct timeval now;
	axdr_state_t xdrs;
	int stat;

	assert(auth != NULL);

	if (auth->ah_cred.oa_base == au->au_origcred.oa_base) {
		/* there is no hope.  Punt */
		return (FALSE);
	}
	au->au_shfaults ++;

	/* first deserialize the creds back into a struct authunix_parms */
	aup.aup_machname = NULL;
	aup.aup_gids = NULL;
	axdrmem_create(&xdrs, au->au_origcred.oa_base,
	    au->au_origcred.oa_length, AXDR_DECODE);
	stat = axdr_authunix_parms(&xdrs, &aup);
	if (! stat)
		goto done;

	/* update the time and serialize in place */
	(void)gettimeofday(&now, NULL);
	aup.aup_time = now.tv_sec;
	xdrs.x_op = AXDR_ENCODE;
	axdr_setpos(&xdrs, 0);
	stat = axdr_authunix_parms(&xdrs, &aup);
	if (! stat)
		goto done;
	auth->ah_cred = au->au_origcred;
	marshal_new_auth(auth);
done:
	/* free the struct authunix_parms created by deserializing */
	xdrs.x_op = AXDR_FREE;
	(void)axdr_authunix_parms(&xdrs, &aup);
	axdr_destroy(&xdrs);
	return (stat);
}

static void
authunix_destroy(ar_auth_t *auth)
{
	struct audata *au;

	assert(auth != NULL);

	au = AUTH_PRIVATE(auth);
	mem_free(au->au_origcred.oa_base, au->au_origcred.oa_length);

	if (au->au_shcred.oa_base != NULL)
		mem_free(au->au_shcred.oa_base, au->au_shcred.oa_length);

	mem_free(auth->ah_private, sizeof(struct audata));

	if (auth->ah_verf.oa_base != NULL)
		mem_free(auth->ah_verf.oa_base, auth->ah_verf.oa_length);

	mem_free(auth, sizeof(*auth));
}

/*
 * Marshals (pre-serializes) an auth struct.
 * sets private data, au_marshed and au_mpos
 */
static void
marshal_new_auth(ar_auth_t *auth)
{
	axdr_state_t	xdr_stream;
	axdr_state_t	*xdrs = &xdr_stream;
	struct audata *au;

	assert(auth != NULL);

	au = AUTH_PRIVATE(auth);
	axdrmem_create(xdrs, au->au_marshed, AR_MAX_AUTH_BYTES, AXDR_ENCODE);
	if ((! axdr_opaque_auth(xdrs, &(auth->ah_cred))) ||
	    (! axdr_opaque_auth(xdrs, &(auth->ah_verf))))
		warnx("auth_unix.c - Fatal marshalling problem");
	else
		au->au_mpos = axdr_getpos(xdrs);
	axdr_destroy(xdrs);
}
