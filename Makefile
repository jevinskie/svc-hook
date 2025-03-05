#!/usr/bin/env make
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 Akira Moroo

PROGS = libsvchook.so aarch64-svc-finder-macho
PARANOID := 1

CLANG_FORMAT ?= clang-format

CLEANFILES = $(PROGS) *.o *.d *.dSYM/

CC := clang
# CFLAGS = -O3
CFLAGS = -O0
# CFLAGS += -pipe
CFLAGS += -g
# CFLAGS += -Werror
CFLAGS += -Wall
CFLAGS += -Wunused-function
CFLAGS += -Wextra
# CFLAGS += -fPIC

CXXFLAGS := $(CFLAGS) -std=gnu++2b -isystem /opt/homebrew/opt/fmt/include -L /opt/homebrew/opt/fmt/lib

ifeq ($(PARANOID), 1)
CFLAGS += -DPARANOID_MODE
endif

ifeq ($(SYSCALL_RECORD), 1)
CFLAGS += -DSUPPLEMENTAL__SYSCALL_RECORD
endif

LDFLAGS += -shared
# LDFLAGS += -rdynamic
# LDFLAGS += -ldl

C_SRCS = main.c
OBJS = $(C_SRCS:.c=.o)

all: $(PROGS)

libsvchook.so: main.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

aarch64-svc-finder-macho: aarch64-svc-finder-macho.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) -lfmt

clean:
	-@rm -rf $(CLEANFILES)

fmt:
	$(CLANG_FORMAT) -i $(C_SRCS)

.PHONY: all clean fmt
