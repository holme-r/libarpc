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
 * Copyright (c) 1986 - 1991 by Sun Microsystems, Inc.
 */

/*
 * auth_des.h, Protocol for DES style authentication for RPC
 */

#ifndef _LIBARPC_AUTH_DES_
#define _LIBARPC_AUTH_DES_

/*
 * There are two kinds of "names": fullnames and nicknames
 */
typedef enum ar_authdes_namekind_e {
	AR_ADN_FULLNAME, 
	AR_ADN_NICKNAME
} ar_authdes_namekind_t;

/*
 * A fullname contains the network name of the client, 
 * a conversation key and the window
 */
typedef struct ar_authdes_fullname_s {
	char *name;	     /* network name of client, up to MAXNETNAMELEN */
	ar_des_block_t key;  /* conversation key */
	u_long window;	     /* associated window */
} ar_authdes_fullname_t;


/*
 * A credential 
 */
typedef struct ar_authdes_cred_s {
	ar_authdes_namekind_t adc_namekind;
	ar_authdes_fullname_t adc_fullname;
	u_long adc_nickname;
} ar_authdes_cred_t;



/*
 * A des authentication verifier 
 */
typedef struct ar_authdes_verf_s {
	union {
		struct timeval adv_ctime;	/* clear time */
		ar_des_block_t adv_xtime;		/* crypt time */
	} aadv_time_u;
	u_long aadv_int_u;
} ar_authdes_verf_t;

/*
 * des authentication verifier: client variety
 *
 * adv_timestamp is the current time.
 * adv_winverf is the credential window + 1.
 * Both are encrypted using the conversation key.
 */
#define aadv_timestamp	aadv_time_u.adv_ctime
#define aadv_xtimestamp	aadv_time_u.adv_xtime
#define aadv_winverf	aadv_int_u

/*
 * des authentication verifier: server variety
 *
 * adv_timeverf is the client's timestamp + client's window
 * adv_nickname is the server's nickname for the client.
 * adv_timeverf is encrypted using the conversation key.
 */
#define aadv_timeverf	aadv_time_u.adv_ctime
#define aadv_xtimeverf	aadv_time_u.adv_xtime
#define aadv_nickname	aadv_int_u

/*
 * Map a des credential into a unix cred.
 *
 */
__BEGIN_DECLS
extern int ar_authdes_getucred(ar_authdes_cred_t *, uid_t *, 
			       gid_t *, int *, gid_t * );
extern axdr_ret_t	axdr_authdes_cred(axdr_state_t *, ar_authdes_cred_t *);
extern axdr_ret_t	axdr_authdes_verf(axdr_state_t *, ar_authdes_verf_t *);
extern int		ar_rtime(dev_t, arpc_addr_t *, int, struct timeval *,
				 struct timeval *);
extern void		ar_kgetnetname(char *);
extern ar_auth_stat_t	ar_svcauth_des(struct ar_svc_req_s *, arpc_msg_t *);
__END_DECLS

#endif /* ndef _LIBARPC_AUTH_DES_ */
