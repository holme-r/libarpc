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
 * Copyright (c) 1986 - 1991, 1994, 1996, 1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * stat.h - remote procedure call status enum
 *
 */

#ifndef	_LIBARPC_STAT_H
#define	_LIBARPC_STAT_H

/* #pragma ident	"@(#)clnt_stat.h	1.2	97/04/28 SMI" */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ar_stat_e {
	ARPC_SUCCESS = 0,		/* call succeeded */
	/*
	 * local errors
	 */
	ARPC_CANTENCODEARGS = 1,	/* can't encode arguments */
	ARPC_CANTDECODERES = 2,		/* can't decode results */
	ARPC_CANTSEND = 3,		/* failure in sending call */
	ARPC_CANTRECV = 4,
	/* failure in receiving result */
	ARPC_TIMEDOUT = 5,		/* call timed out */
	ARPC_INTR = 18,			/* call interrupted */
	/*
	 * remote errors
	 */
	ARPC_VERSMISMATCH = 6,		/* rpc versions not compatible */
	ARPC_AUTHERROR = 7,		/* authentication error */
	ARPC_PROGUNAVAIL = 8,		/* program not available */
	ARPC_PROGVERSMISMATCH = 9,	/* program version mismatched */
	ARPC_PROCUNAVAIL = 10,		/* procedure unavailable */
	ARPC_CANTDECODEARGS = 11,	/* decode arguments error */
	ARPC_SYSTEMERROR = 12,		/* generic "other problem" */

	/*
	 * Arpc_call & clnt_create errors
	 */
	ARPC_UNKNOWNHOST = 13,		/* unknown host name */
	ARPC_UNKNOWNPROTO = 17,		/* unknown protocol */
	ARPC_UNKNOWNADDR = 19,		/* Remote address unknown */
	ARPC_NOBROADCAST = 21,		/* Broadcasting not supported */

	/*
	 * rpcbind errors
	 */
	ARPC_RPCBFAILURE = 14,		/* the pmapper failed in its call */
	ARPC_PROGNOTREGISTERED = 15,	/* remote program is not registered */
	ARPC_N2AXLATEFAILURE = 22,
	/* Name to address translation failed */
	/*
	 * Misc error in the TLI library
	 */
	ARPC_TLIERROR = 20,
	/*
	 * unspecified error
	 */
	ARPC_FAILED = 16,
	/*
	 * asynchronous errors
	 */
	ARPC_INPROGRESS = 24,
	ARPC_CANTCONNECT = 26,		/* couldn't make connection (cots) */
	ARPC_XPRTFAILED = 27,		/* received discon from remote (cots) */
	ARPC_CANTCREATESTREAM = 28,	/* can't push rpc module (cots) */
	ARPC_ERRNO = 29			/* local system error */
} ar_stat_t;

/* Auth errors */
/*
 * Status returned from authentication check
 */
typedef enum ar_auth_stat_e {
	AR_AUTH_OK=0,
	/*
	 * failed at remote end
	 */
	AR_AUTH_BADCRED=1,		/* bogus credentials (seal broken) */
	AR_AUTH_REJECTEDCRED=2,		/* client should begin new session */
	AR_AUTH_BADVERF=3,		/* bogus verifier (seal broken) */
	AR_AUTH_REJECTEDVERF=4,		/* verifier expired or was replayed */
	AR_AUTH_TOOWEAK=5,		/* rejected due to security reasons */
	/*
	 * failed locally
	*/
	AR_AUTH_INVALIDRESP=6,		/* bogus response verifier */
	AR_AUTH_FAILED=7		/* some unknown reason */
	/*
	 * kerberos errors
	 */
	,
	AR_AUTH_KERB_GENERIC = 8,	/* kerberos generic error */
	AR_AUTH_TIMEEXPIRE = 9,		/* time of credential expired */
	AR_AUTH_TKT_FILE = 10,		/* something wrong with ticket file */
	AR_AUTH_DECODE = 11,		/* can't decode authenticator */
	AR_AUTH_NET_ADDR = 12		/* wrong net address in ticket */
} ar_auth_stat_t;

/*
 * Error info.
 */
typedef struct arpc_err_s {
	ar_stat_t re_status;
	union {
		int RE_errno;		/* related system error */
		ar_auth_stat_t RE_why;	/* why the auth error occurred */
		struct {
			arpcvers_t low;	/* lowest version supported */
			arpcvers_t high;	/* highest version supported */
		} RE_vers;
		struct {		/* maybe meaningful if ARPC_FAILED */
			int32_t s1;
			int32_t s2;
		} RE_lb;		/* life boot & debugging only */
	} ru;
#define	re_errno	ru.RE_errno
#define	re_why		ru.RE_why
#define	re_vers		ru.RE_vers
#define	re_lb		ru.RE_lb
} arpc_err_t;

/*
 * If a connection creation fails, the following allows the user to 
 * figure out why.
 */
typedef struct arpc_createerr_s {
	/* cf_stat == cf_error.re_status, unless 
	 * cf_stat == ARPC_RPCBFAILURE, in which case, 
	 * the cf_error structure contains the underlying bind error
	 * code. 
	 */
	ar_stat_t cf_stat;
	arpc_err_t cf_error; 
} arpc_createerr_t;

const char *ar_strstat(ar_stat_t stat);
const char *ar_strauthstat(ar_auth_stat_t stat);

extern void ar_strerror(const arpc_err_t *, char *buf, size_t len);
extern char *ar_astrerror(const arpc_err_t *);
extern void ar_strcreateerror(const arpc_createerr_t *, char *buf, size_t len);
extern char *ar_astrcreateerror(const arpc_createerr_t *);

#ifdef __cplusplus
}
#endif

#endif	/* !_LIBARPC_CLNT_STAT_H */
