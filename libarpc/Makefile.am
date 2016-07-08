## Process this file with automake to create Makefile.in.

## NOTE: this file doesn't really try to be complete.  In particular
## `make dist' won't work at all.  We're just aiming to get the
## program built.  We also don't bother trying to assemble code, or
## anything like that.

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -I$(top_srcdir)/libarpc \
	-D_BSD_SOURCE -DPORTMAP -DINET6 -DVERSION="\"$(VERSION)\""
AM_CFLAGS = -Wall -pipe
CLEANFILES =
EXTRA_DIST =

lib_LTLIBRARIES = libarpc.la
libarpc_la_LDFLAGS = -lpthread -lssl

# Only files ported so far
libarpc_ladir = $(includedir)/libarpc
libarpc_la_HEADERS = \
	arpc.h arpc_io.h arpc_msg.h arpcent.h \
	auth.h auth_des.h auth_unix.h \
	axdr.h \
	clnt.h pmap_clnt.h rpcb_clnt.h \
	stack.h \
	stat.h \
	svc.h svc_auth.h \
	types.h \
	vcd_tls.h

libarpc_la_SOURCES = \
	rpc_prot.c rpc_io.c rpc_vc.c rpc_dg.c rpc_commondata.c \
	rpcb_clnt.c rpcb_prot.c rpcb_st_xdr.c rpc_generic.c \
	pmap_prot.c pmap_prot2.c \
	auth_none.c auth_unix.c authunix_prot.c \
	clnt_generic.c \
	svc_auth.c svc.c svc_generic.c \
	vcd_tls.c \
	stack.c \
 	rpc_com.h xdr_com.h \
	compat.h namespace.h un-namespace.h reentrant.h

# FIXME
#libarpc_la_SOURCES = auth_none.c auth_unix.c authunix_prot.c \
#	bindresvport.c clnt_bcast.c \
#        clnt_dg.c clnt_generic.c clnt_perror.c clnt_raw.c clnt_simple.c \
#        clnt_vc.c rpc_dtablesize.c getnetconfig.c getnetpath.c getrpcent.c \
#        getrpcport.c mt_misc.c pmap_clnt.c pmap_getmaps.c pmap_getport.c \
#        pmap_prot.c pmap_prot2.c pmap_rmt.c rpc_prot.c rpc_commondata.c \
#        rpc_callmsg.c rpc_generic.c rpc_soc.c rpcb_clnt.c rpcb_prot.c \
#        rpcb_st_xdr.c svc.c svc_auth.c svc_dg.c svc_auth_unix.c svc_generic.c \
#        svc_raw.c svc_run.c svc_simple.c svc_vc.c getpeereid.c \
#        auth_time.c auth_des.c authdes_prot.c

## XDR
libarpc_la_SOURCES += xdr.c xdr_rec.c xdr_array.c xdr_float.c xdr_mem.c \
	xdr_reference.c xdr_stdio.c xdr_sizeof.c xdr_print.c

## Secure-RPC
if GSS
    libarpc_la_SOURCES += auth_gss.c authgss_prot.c svc_auth_gss.c \
		svc_auth_none.c
    libarpc_la_LDFLAGS += $(GSSGLUE_LIBS)
    libarpc_la_CFLAGS = -DHAVE_RPCSEC_GSS $(GSSGLUE_CFLAGS)
endif

## libarpc_a_SOURCES += key_call.c key_prot_xdr.c getpublickey.c
## libarpc_a_SOURCES += netname.c netnamer.c rpcdname.c \
## libarpc_a_SOURCES += rtime.c \
## auth_time.c auth_des.c authdes_prot.c 

## Generated
EXTRA_DIST += rpcb_prot.x pmap_prot.x
nodist_libarpc_la_SOURCES = rpcb_prot.h pmap_prot.h

rpcb_clnt.c: rpcb_prot.h pmap_prot.h

rpcb_prot.h: $(top_srcdir)/libarpc/rpcb_prot.x
	$(top_builddir)/build/buildrpcgen -h -o rpcb_prot.h \
		$(top_srcdir)/libarpc/rpcb_prot.x

pmap_prot.h: $(top_srcdir)/libarpc/pmap_prot.x
	$(top_builddir)/build/buildrpcgen -h -o pmap_prot.h \
		$(top_srcdir)/libarpc/pmap_prot.x

CLEANFILES += rpcb_prot.h pmap_prot.h

dist_man_MANS = axdr.3 bindresvport.3 des_crypt.3 \
	getnetconfig.3 getnetpath.3 getrpcent.3 getrpcport.3 \
	netconfig.5 publickey.3 publickey.5 arpc.3 rpc.5 rpcbind.3 \
	rpc_clnt_auth.3 rpc_clnt_calls.3 rpc_clnt_create.3 \
	rpc_secure.3 rpc_soc.3 \
	rpc_svc_calls.3 rpc_svc_create.3 rpc_svc_err.3 rpc_svc_reg.3 \
	rpc_xdr.3 rtime.3
