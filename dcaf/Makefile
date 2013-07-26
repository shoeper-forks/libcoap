# Makefile for libcoap
#
# Copyright (C) 2010--2013 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the CoAP library libcoap. Please see
# README for terms of use. 

# the library's version
VERSION:=5.0.0

# tools

SHELL = /bin/sh
MKDIR = mkdir

abs_builddir = /home/bergmann/develop/libcoap-cbio/dcaf
top_builddir = ..
top_srcdir = ..
# files and flags
PROGRAMS:=dcaf-client as
SOURCES:= dcaf-client.c address.c as.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
#CFLAGS:=-g -Wall -ansi -pedantic -I..
CFLAGS:=-g -Wall -g -O2
CPPFLAGS:=-I$(top_srcdir) -I/home/bergmann/include
DISTDIR?=$(top_builddir)/libcoap-5.0.0
FILES:=Makefile.in $(SOURCES)
LDFLAGS:=-L$(top_builddir) -L/home/bergmann/lib
LDLIBS:=-lcoap -ltinydtls 
libcoap =$(top_builddir)/libcoap.a

.PHONY: clean distclean

.SUFFIXES:
.SUFFIXES:      .c .o

all:	$(PROGRAMS)

check:	
	echo DISTDIR: $(DISTDIR)
	echo top_builddir: $(top_builddir)

dcaf-client: dcaf-client.o address.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	@rm -f $(PROGRAMS) $(OBJECTS)

distclean:	clean
	@rm -rf $(DISTDIR)
	@rm -f *~ 

dist:	$(FILES)
	test -d $(DISTDIR)/examples || mkdir $(DISTDIR)/examples
	cp $(FILES) $(DISTDIR)/examples
