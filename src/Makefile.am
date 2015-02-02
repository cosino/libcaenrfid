# @configure_input@

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = @EXTRA_CFLAGS@ -include @build_os@.h

lib_LTLIBRARIES = libcaenrfid.la

libcaenrfid_la_SOURCES = caenrfid.c \
			@build_os@.c
libcaenrfid_la_HEADERS = caenrfid.h caenrfid_old.h
noinst_HEADERS = logging.h caenrfid_proto.h \
			@build_os@.h

libcaenrfid_ladir = $(includedir)
