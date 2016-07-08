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
 * auth_none.c
 * Creates a client authentication handle for passing "null"
 * credentials and verifiers to remote systems.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#include "compat.h"

#include <sys/cdefs.h>
#include <assert.h>
#include <stdlib.h>
#include <libarpc/types.h>
#include <libarpc/axdr.h>
#include <libarpc/arpc.h>
#include <libarpc/auth.h>

#include "rpc_com.h"

#define MAX_MARSHAL_SIZE 20

/*
 * Authenticator operations routines
 */

static int authnone_marshal(ar_auth_t *, arpc_msg_t *msg);
static int authnone_cleanup(ar_auth_t *, arpc_msg_t *msg);

static void authnone_verf(ar_auth_t *);
static int authnone_validate(ar_auth_t *, ar_opaque_auth_t *);
static int authnone_refresh(ar_auth_t *, void *);
static void authnone_destroy(ar_auth_t *);

struct authnone_private {
	ar_auth_t	no_client;
};

static ar_auth_ops_t authnone_ops = {
	&authnone_verf,
	&authnone_marshal,
	&authnone_cleanup,
	&authnone_validate,
	&authnone_refresh,
	&authnone_destroy
};

ar_auth_t *
ar_authnone_create(void)
{
	struct authnone_private *ap;

	ap = (struct authnone_private *)calloc(1, sizeof (*ap));
	if (!ap) {
		return NULL;
	}

	ap->no_client.ah_cred = ar_null_auth;
	ap->no_client.ah_verf = ar_null_auth;
	ap->no_client.ah_ops = &authnone_ops;
	ap->no_client.ah_private = ap;

	return (&ap->no_client);
}

/*ARGSUSED*/
static bool_t
authnone_marshal(ar_auth_t *client, arpc_msg_t *msg)
{
	assert(msg != NULL);

	msg->arm_call.acb_cred = ar_null_auth;
	msg->arm_call.acb_verf = ar_null_auth;

	return TRUE;
}

static int
authnone_cleanup(ar_auth_t *client, arpc_msg_t *msg)
{
	return 0;
}

/* All these unused parameters are required to keep ANSI-C from grumbling */
/*ARGSUSED*/
static void
authnone_verf(ar_auth_t *client)
{
}

/*ARGSUSED*/
static bool_t
authnone_validate(ar_auth_t *client, ar_opaque_auth_t *opaque)
{
	return (TRUE);
}

/*ARGSUSED*/
static bool_t
authnone_refresh(ar_auth_t *client, void *dummy)
{
	return (FALSE);
}

/*ARGSUSED*/
static void
authnone_destroy(ar_auth_t *client)
{
	if (client) {
		free(client->ah_private);
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
