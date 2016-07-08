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
 * authunix_prot.c
 * XDR for UNIX style authentication parameters for RPC
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#include "compat.h"
#include "namespace.h"
#include <sys/cdefs.h>
#include <assert.h>

#include <libarpc/types.h>
#include <libarpc/axdr.h>
#include <libarpc/auth.h>
#include <libarpc/auth_unix.h>
#include "un-namespace.h"

/*
 * XDR for unix authentication parameters.
 */
axdr_ret_t
axdr_authunix_parms(axdr_state_t *xdrs, ar_authunix_parms_t *p)
{

	assert(xdrs != NULL);
	assert(p != NULL);

	if (axdr_u_long(xdrs, &(p->aup_time))
	    && axdr_string(xdrs, &(p->aup_machname), MAX_MACHINE_NAME)
	    && axdr_int(xdrs, &(p->aup_uid))
	    && axdr_int(xdrs, &(p->aup_gid))
	    && axdr_array(xdrs, (caddr_t *)&(p->aup_gids),
		    &(p->aup_len), NGRPS, sizeof(int), (axdrproc_t)axdr_int)) {
		return (TRUE);
	}
	return (FALSE);
}
