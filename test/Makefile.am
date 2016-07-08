ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -I$(top_srcdir)/libarpc $(ATF_INCLUDES)
LDADD = ../libarpc/libarpc.la -latf-c -lssl $(ATF_LDFLAGS)
CLEANFILES =
EXTRA_DIST =

if ATF

tests_PROGRAMS = t_xdr t_rpc
tests_DATA = Atffile

t_xdr_SOURCES = test_xdr.c
t_rpc_SOURCES = test_rpc.c test_rpc.h

## Generated
EXTRA_DIST += testobjs_xdr.x testobjs_rpc.x
nodist_t_xdr_SOURCES = testobjs_xdr.h testobjs_xdr.c
nodist_t_rpc_SOURCES = testobjs_rpc.h testobjs_rpc.c
test_xdr.$(OBJEXT): testobjs_xdr.h 
test_rpc.$(OBJEXT): testobjs_rpc.h

testobjs_xdr.h: $(top_srcdir)/test/testobjs_xdr.x
	$(top_builddir)/build/buildrpcgen -h -o $@ $<
testobjs_xdr.c: $(top_srcdir)/test/testobjs_xdr.x
	$(top_builddir)/build/buildrpcgen -c -o $@ $<

testobjs_rpc.h: $(top_srcdir)/test/testobjs_rpc.x
	$(top_builddir)/build/buildrpcgen -h -o $@ $<
testobjs_rpc.c: $(top_srcdir)/test/testobjs_rpc.x
	$(top_builddir)/build/buildrpcgen -c -o $@.xdr $<
	$(top_builddir)/build/buildrpcgen -l -o $@.clnt $<
	$(top_builddir)/build/buildrpcgen -m -o $@.srv $<
	cat $@.xdr $@.clnt $@.srv > $@
	rm $@.xdr $@.clnt $@.srv

CLEANFILES += testobjs_xdr.h testobjs_rpc.h
CLEANFILES += testobjs_xdr.c testobjs_rpc.c

#
# Derived from ATF autoconf
#

TEST_ENVIRONMENT = PATH=$(prefix)/bin:$${PATH} \
		   PKG_CONFIG_PATH=$(prefix)/lib/pkgconfig

testsdir = $(exec_prefix)/tests
pkgtestsdir = $(testsdir)/$(PACKAGE)

installcheck-local: installcheck-atf
.PHONY: installcheck-atf
installcheck-atf:
	logfile=$$(pwd)/installcheck.log; \
	fifofile=$$(pwd)/installcheck.fifo; \
	cd $(pkgtestsdir); \
	rm -f $${fifofile}; \
	mkfifo $${fifofile}; \
	cat $${fifofile} | tee $${logfile} | \
		$(TESTS_ENVIRONMENT) $(ATFREPORT) & \
		$(TESTS_ENVIRONMENT) $(ATFRUN) >>$${fifofile}; \
	res=$${?}; \
	wait; \
	rm $${fifofile}; \
	echo; \
	echo "The verbatim output of atf-run has been saved to" \
	     "installcheck.log; exit was $${res}"; \
	test $${res} -eq 0
CLEANFILES += installcheck.fifo installcheck.log

pkgtests_DATA = Atffile
EXTRA_DIST += $(pkgtests_DATA)

endif # HAVE_ATF
