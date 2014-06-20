## Process this file with automake to produce Makefile.in

TESTS = check_xsdc
check_PROGRAMS = check_xsdc
check_xsdc_SOURCES = check_xsdc.cpp $(top_builddir)/src/xsdc.h
check_xsdc_CFLAGS = @CHECK_CFLAGS@
check_xsdc_LDADD = $(top_builddir)/src/xsdc.o @CHECK_LIBS@
