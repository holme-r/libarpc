/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
/*
 * warmstart.c
 * Allows for gathering of registrations from an earlier dumped file.
 *
 * Copyright (c) 1990 by Sun Microsystems, Inc.
 */

/*
 * #ident	"@(#)warmstart.c	1.7	93/07/05 SMI"
 * $FreeBSD: src/usr.sbin/rpcbind/warmstart.c,v 1.3 2003/01/01 18:49:03 schweikh Exp $/
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <libarpc/arpc.h>
#include <libarpc/axdr.h>
#include "rpcb_prot.h"
#include <netinet/in.h>
#include "pmap_prot.h"
#include <syslog.h>
#include <unistd.h>

#include "rpcbind.h"

/*
 * XXX this code is unsafe and is not used. It should be made safe.
 */


/* These files keep the pmap_list and rpcb_list in XDR format */
#define	RPCBFILE	"/tmp/rpcbind.file"
#define	PMAPFILE	"/tmp/portmap.file"

static bool_t write_struct(char *, axdrproc_t, void *);
static bool_t read_struct(char *, axdrproc_t, void *);

static bool_t
write_struct(char *filename, axdrproc_t structproc, void *list)
{
	FILE *fp;
	axdr_state_t xdrs;
	mode_t omask;

	omask = umask(077);
	fp = fopen(filename, "w");
	if (fp == NULL) {
		int i;

		for (i = 0; i < 10; i++)
			close(i);
		fp = fopen(filename, "w");
		if (fp == NULL) {
			syslog(LOG_ERR,
				"cannot open file = %s for writing", filename);
			syslog(LOG_ERR, "cannot save any registration");
			return (FALSE);
		}
	}
	(void) umask(omask);
	axdrstdio_create(&xdrs, fp, AXDR_ENCODE);

	if (structproc(&xdrs, list) != AXDR_DONE) {
		syslog(LOG_ERR, "rpcbind: xdr_%s: failed", filename);
		axdr_destroy(&xdrs);
		fclose(fp);
		return (FALSE);
	}
	axdr_destroy(&xdrs);
	fclose(fp);
	return (TRUE);
}

static bool_t
read_struct(char *filename, axdrproc_t structproc, void *list)
{
	FILE *fp;
	axdr_state_t xdrs;
	struct stat sbuf;

	if (stat(filename, &sbuf) != 0) {
		fprintf(stderr,
		"rpcbind: cannot stat file = %s for reading\n", filename);
		goto error;
	}
	if ((sbuf.st_uid != 0) || (sbuf.st_mode & S_IRWXG) ||
	    (sbuf.st_mode & S_IRWXO)) {
		fprintf(stderr,
		"rpcbind: invalid permissions on file = %s for reading\n",
			filename);
		goto error;
	}
	fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr,
		"rpcbind: cannot open file = %s for reading\n", filename);
		goto error;
	}
	axdrstdio_create(&xdrs, fp, AXDR_DECODE);

	if (structproc(&xdrs, list) != AXDR_DONE) {
		fprintf(stderr, "rpcbind: xdr_%s: failed\n", filename);
		axdr_destroy(&xdrs);
		fclose(fp);
		goto error;
	}
	axdr_destroy(&xdrs);
	fclose(fp);
	return (TRUE);

error:	fprintf(stderr, "rpcbind: will start from scratch\n");
	return (FALSE);
}

void
write_warmstart()
{
	(void) write_struct(RPCBFILE, 
			    (axdrproc_t)axdr_rpcblist_ptr, &list_rbl);
#ifdef PORTMAP
	(void) write_struct(PMAPFILE, 
			    (axdrproc_t)axdr_ar_pmaplist_ptr, &list_pml);
#endif

}

void
read_warmstart()
{
	rpcblist_ptr tmp_rpcbl = NULL;
	ar_pmaplist_t *tmp_pmapl = NULL;
	int ok1, ok2 = TRUE;

	ok1 = read_struct(RPCBFILE, (axdrproc_t)axdr_rpcblist_ptr, &tmp_rpcbl);
	if (ok1 == FALSE) {
		return;
	}
	ok2 = read_struct(PMAPFILE, (axdrproc_t)axdr_ar_pmaplist_ptr, 
			  &tmp_pmapl);
	if (ok2 == FALSE) {
		axdr_free((axdrproc_t)axdr_rpcblist_ptr, (char *)&tmp_rpcbl);
		return;
	}
	axdr_free((axdrproc_t)axdr_rpcblist_ptr, (char *)&list_rbl);
	list_rbl = tmp_rpcbl;
	axdr_free((axdrproc_t)axdr_ar_pmaplist_ptr, (char *)&list_pml);
	list_pml = tmp_pmapl;
}
