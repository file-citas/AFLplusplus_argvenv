#
# american fuzzy lop++ - argvfuzz
# --------------------------------
#
# Copyright 2019-2022 Kjell Braden <afflux@pentabarf.de>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

.PHONY: all install clean

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl

CFLAGS = -fPIC -Wall -Wextra
LDFLAGS = -shared

UNAME_SAYS_LINUX=$(shell uname | grep -E '^Linux|^GNU' >/dev/null; echo $$?)
UNAME_SAYS_LINUX:sh=uname | grep -E '^Linux|^GNU' >/dev/null; echo $$?

_LDFLAGS_ADD=$(UNAME_SAYS_LINUX:1=)
LDFLAGS_ADD=$(_LDFLAGS_ADD:0=-ldl)
LDFLAGS  += $(LDFLAGS_ADD)

# on gcc for arm there is no -m32, but -mbe32
M64FLAG = -m64 -Wno-unused-function

CC_IS_GCC=$(shell $(CC) --version 2>/dev/null | grep -q gcc; echo $$?)
CC_IS_GCC:sh=$(CC) --version 2>/dev/null | grep -q gcc; echo $$?
CC_IS_ARMCOMPILER=$(shell $(CC) -v 2>&1 >/dev/null | grep -q arm; echo $$?)
CC_IS_ARMCOMPILER:sh=$(CC) -v 2>&1 >/dev/null | grep -q arm; echo $$?

all: argvfuzz64.so argvdump64.so

argvfuzz64.so: argvfuzz.c
	$(CC) $(M64FLAG) $(CFLAGS) $^ $(LDFLAGS) -o $@

argvdump64.so: argvdump.c
	$(CC) $(M64FLAG) $(CFLAGS) $^ $(LDFLAGS) -luuid -o $@

install: argvfuzz64.so argvdump64.so
	install -d -m 755 $(DESTDIR)$(HELPER_PATH)/
	if [ -f argvfuzz64.so ]; then set -e; install -m 755 argvfuzz64.so $(DESTDIR)$(HELPER_PATH)/; fi
	if [ -f argvdump64.so ]; then set -e; install -m 755 argvdump64.so $(DESTDIR)$(HELPER_PATH)/; fi
	cp argv-fuzz-inl.h $(DESTDIR)$(HELPER_PATH)

clean:
	rm -f argvfuzz64.so argvdump64.so
