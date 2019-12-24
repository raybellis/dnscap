MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = frootmon.la
frootmon_la_SOURCES = frootmon.c
frootmon_la_LDFLAGS = -module -avoid-version
