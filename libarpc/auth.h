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
 * auth.h, Authentication interface.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * The data structures are completely opaque to the client.  The client
 * is required to pass an AUTH * to routines that create rpc
 * "sessions".
 */

#ifndef _LIBARPC_AUTH_H
#define _LIBARPC_AUTH_H

#include <libarpc/axdr.h>
#include <libarpc/stat.h>
#include <sys/cdefs.h>
#include <sys/socket.h>

#define AR_MAX_AUTH_BYTES	400
#define AR_MAXNETNAMELEN	255 /* maximum length of network user's name */

/*
 *  Client side authentication/security data
 */

typedef struct ar_sec_data_s {
	u_int	secmod;		/* security mode number e.g. in nfssec.conf */
	u_int	rpcflavor;	/* rpc flavors:AUTH_UNIX,AUTH_DES,RPCSEC_GSS */
	int	flags;		/* AUTH_F_xxx flags */
	caddr_t data;		/* opaque data per flavor */
} ar_sec_data_t;

/*
 * AUTH_DES flavor specific data from sec_data opaque data field.
 * AUTH_KERB has the same structure.
 */
typedef struct ar_k4_clntdata_s {
	arpc_addr_t	syncaddr;	/* time sync addr */
	struct knetconfig *knconf;	/* knetconfig info that associated */
					/* with the syncaddr. */
	char		*netname;	/* server's netname */
	int		netnamelen;	/* server's netname len */
} ar_k4_clntdata_t;

#ifdef KERBEROS
/*
 * flavor specific data to hold the data for AUTH_DES/AUTH_KERB(v4)
 * in sec_data->data opaque field.
 */
typedef struct ar_krb4_svcdata_s {
	int		window;		/* window option value */
} ar_krb4_svcdata_t;
 
typedef struct krb4_svc_data	des_svcdata_t;
#endif /* KERBEROS */

/*
 * authentication/security specific flags
 */
#define AR_AUTH_F_RPCTIMESYNC	0x001	/* use RPC to do time sync */
#define AR_AUTH_F_TRYNONE	0x002	/* allow fall back to AUTH_NONE */

union ar_des_block_u {
	struct {
		uint32_t high;
		uint32_t low;
	} key;
	char c[8];
};
typedef union ar_des_block_u ar_des_block_t;
__BEGIN_DECLS
extern axdr_ret_t axdr_des_block(axdr_state_t *, ar_des_block_t *);
__END_DECLS

/*
 * Authentication info.  Opaque to client.
 */
typedef struct ar_opaque_auth_s {
	enum_t	oa_flavor;		/* flavor of auth */
	caddr_t	oa_base;		/* address of more auth stuff */
	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
} ar_opaque_auth_t;

typedef struct ar_auth_s ar_auth_t;
typedef struct ar_auth_ops_s ar_auth_ops_t;
struct arpc_msg_s;

struct ar_auth_ops_s {
	void	(*ah_nextverf)(ar_auth_t *);
	/* nextverf & serialize */
	int	(*ah_marshal_msg)(ar_auth_t *, struct arpc_msg_s *);
	/* free up auth msg elements set by marshal_msg */
	int	(*ah_cleanup_msg)(ar_auth_t *, struct arpc_msg_s *);
	/* validate verifier */
	int	(*ah_validate)(ar_auth_t *, ar_opaque_auth_t *);
	/* refresh credentials */
	int	(*ah_refresh)(ar_auth_t *, void *);
	/* destroy this structure */
	void	(*ah_destroy)(ar_auth_t *);
};


/*
 * Auth handle, interface to client side authenticators.
 */
struct ar_auth_s {
	ar_opaque_auth_t	ah_cred;
	ar_opaque_auth_t	ah_verf;
	ar_des_block_t		ah_key;
	ar_auth_ops_t		*ah_ops;
	void			*ah_private;
};


/*
 * Authentication ops.
 * The ops and the auth handle provide the interface to the authenticators.
 *
 * AUTH	*auth;
 * XDR	*xdrs;
 * struct opaque_auth verf;
 */
#define AR_AUTH_NEXTVERF(auth)		\
		((*((auth)->ah_ops->ah_nextverf))(auth))
#define ar_auth_nextverf(auth)		\
		((*((auth)->ah_ops->ah_nextverf))(auth))

#define AR_AUTH_MARSHALL_MSG(auth, msg)	\
		((*((auth)->ah_ops->ah_marshal_msg))(auth, msg))
#define ar_auth_marshall_msg(auth, msg)	\
		((*((auth)->ah_ops->ah_marshal_msg))(auth, msg))

#define AR_AUTH_CLEANUP_MSG(auth, msg)	\
		((*((auth)->ah_ops->ah_cleanup_msg))(auth, msg))
#define ar_auth_CLEANUP_MSG(auth, msg)	\
		((*((auth)->ah_ops->ah_cleanup_msg))(auth, msg))

#define AR_AUTH_VALIDATE(auth, verfp)	\
		((*((auth)->ah_ops->ah_validate))((auth), verfp))
#define ar_auth_validate(auth, verfp)	\
		((*((auth)->ah_ops->ah_validate))((auth), verfp))

#define AR_AUTH_REFRESH(auth, msg)		\
		((*((auth)->ah_ops->ah_refresh))(auth, msg))
#define ar_auth_refresh(auth, msg)		\
		((*((auth)->ah_ops->ah_refresh))(auth, msg))

#define AR_AUTH_DESTROY(auth)		\
		((*((auth)->ah_ops->ah_destroy))(auth))
#define ar_auth_destroy(auth)		\
		((*((auth)->ah_ops->ah_destroy))(auth))

__BEGIN_DECLS
extern ar_opaque_auth_t ar_null_auth;

/*
 * These are the various implementations of client side authenticators.
 */

/*
 * System style authentication
 * ar_auth_t *authunix_create(machname, uid, gid, len, aup_gids)
 *	char *machname;
 *	int uid;
 *	int gid;
 *	int len;
 *	int *aup_gids;
 */
extern ar_auth_t *ar_authunix_create(char *, int, int, int, int *);
extern ar_auth_t *ar_authunix_create_default(void); /* takes no parameters */
extern ar_auth_t *ar_authnone_create(void);	/* takes no parameters */
/*
 * DES style authentication
 * ar_auth_t *authsecdes_create(servername, window, timehost, ckey)
 * 	char *servername;		- network name of server
 *	u_int window;			- time to live
 * 	const char *timehost;		- optional hostname to sync with
 * 	des_block *ckey;		- optional conversation key to use
 */
extern ar_auth_t *ar_authdes_create(char *, u_int, 
				    struct sockaddr *, ar_des_block_t *);
extern ar_auth_t *ar_authdes_seccreate(const char *, const u_int,
				       const  char *, const ar_des_block_t *);
extern axdr_ret_t axdr_opaque_auth(axdr_state_t *, ar_opaque_auth_t *);

/*
 * Netname manipulation routines.
 */
#if 0
extern int getnetname(char *);
extern int host2netname(char *, const char *, const char *);
extern int user2netname(char *, const uid_t, const char *);
extern int netname2user(char *, uid_t *, gid_t *, int *, gid_t *);
extern int netname2host(char *, char *, const int);
extern void passwd2des( char *, char * );
#endif

/*
 *
 * These routines interface to the keyserv daemon
 *
 */
#if 0
extern int key_decryptsession(const char *, ar_des_block_t *);
extern int key_encryptsession(const char *, ar_des_block_t *);
extern int key_gendes(ar_des_block_t *);
extern int key_setsecret(const char *);
extern int key_secretkey_is_set(void);
#endif

/*
 * Publickey routines.
 */
#if 0
extern int getpublickey (const char *, char *);
extern int getpublicandprivatekey (char *, char *);
extern int getsecretkey (char *, char *, char *);
#endif

#ifdef KERBEROS
/*
 * Kerberos style authentication
 * ar_auth_t *authkerb_seccreate(service, srv_inst, realm, window, timehost, status)
 *	const char *service;			- service name
 *	const char *srv_inst;			- server instance
 *	const char *realm;			- server realm
 *	const u_int window;			- time to live
 *	const char *timehost;			- optional hostname to sync with
 *	int *status;				- kerberos status returned
 */
extern ar_auth_t *ar_authkerb_seccreate(const char *, const char *, 
					const  char *, const u_int, 
					const char *, int *);

/*
 * Map a kerberos credential into a unix cred.
 *
 *	authkerb_getucred(rqst, uid, gid, grouplen, groups)
 *	const struct svc_req *rqst;		- request pointer
 *	uid_t *uid;
 *	gid_t *gid;
 *	short *grouplen;
 *	int *groups;
 *
 */
extern int	ar_authkerb_getucred(/* struct svc_req *, uid_t *, gid_t *,
		    short *, int * */);
#endif /* KERBEROS */

struct ar_svc_req_s;
ar_auth_stat_t ar_svcauth_null (struct ar_svc_req_s *, struct arpc_msg_s *);
ar_auth_stat_t ar__svcauth_short (struct ar_svc_req_s *, struct arpc_msg_s *);
ar_auth_stat_t ar_svcauth_unix (struct ar_svc_req_s *, struct arpc_msg_s *);
__END_DECLS

#define AR_AUTH_NONE	0		/* no authentication */
#define	AR_AUTH_NULL	0		/* backward compatibility */
#define	AR_AUTH_SYS	1		/* unix style (uid, gids) */
#define AR_AUTH_UNIX	AR_AUTH_SYS
#define	AR_AUTH_SHORT	2		/* short hand unix style */
#define AR_AUTH_DH	3		/* for Diffie-Hellman mechanism */
#define AR_AUTH_DES	AR_AUTH_DH	/* for backward compatibility */
#define AR_AUTH_KERB	4		/* kerberos style */

#endif /* !_LIBARPC_AUTH_H */
