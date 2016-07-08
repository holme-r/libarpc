AM_CPPFLAGS = -I$(top_srcdir)/libarpc/include
AM_CPPFLAGS += -I$(top_srcdir)/arpcgen
COMPILE = @CC_FOR_BUILD@

noinst_PROGRAMS = buildrpcgen
buildrpcgen_SOURCES = \
	$(top_srcdir)/arpcgen/rpc_main.c \
	$(top_srcdir)/arpcgen/rpc_clntout.c \
	$(top_srcdir)/arpcgen/rpc_cout.c \
	$(top_srcdir)/arpcgen/rpc_hout.c \
	$(top_srcdir)/arpcgen/rpc_parse.c \
	$(top_srcdir)/arpcgen/rpc_sample.c \
	$(top_srcdir)/arpcgen/rpc_scan.c \
	$(top_srcdir)/arpcgen/rpc_svcout.c \
	$(top_srcdir)/arpcgen/rpc_tblout.c \
	$(top_srcdir)/arpcgen/rpc_util.c \
	$(top_srcdir)/arpcgen/rpc_parse.h \
	$(top_srcdir)/arpcgen/rpc_scan.h \
	$(top_srcdir)/arpcgen/rpc_util.h
