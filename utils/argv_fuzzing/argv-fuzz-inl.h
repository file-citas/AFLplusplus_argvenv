/*
   american fuzzy lop++ - sample argv fuzzing wrapper
   ------------------------------------------------

   Originally written by Michal Zalewski

   Copyright 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This file shows a simple way to fuzz command-line parameters with stock
   afl-fuzz. To use, add:

   #include "/path/to/argv-fuzz-inl.h"

   ...to the file containing main(), ideally placing it after all the
   standard includes. Next, put AFL_INIT_ARGV(); near the very beginning of
   main().

   This will cause the program to read NUL-delimited input from stdin and
   put it in argv[]. Two subsequent NULs terminate the array. Empty
   params are encoded as a lone 0x02. Lone 0x02 can't be generated, but
   that shouldn't matter in real life.

   If you would like to always preserve argv[0], use this instead:
   AFL_INIT_SET0("prog_name");

*/

#ifndef _HAVE_ARGV_FUZZ_INL
#define _HAVE_ARGV_FUZZ_INL


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <linux/limits.h>
#include <uuid/uuid.h>

#define FUZZ_ARGV_BUF_LEN 2048
static int debugprint = 0;
static void dprint(FILE* f, const char* format, ...) {
  va_list args;
  if(!debugprint) return;
  va_start(args, format);
  vfprintf(f, format, args);
  va_end(args);
}

static void check_debug(void) {
  char *env_dprint = getenv("FUZZ_DPRINT");
  debugprint = 0;
  if(env_dprint && atoi(env_dprint) == 1) {
    debugprint = 1;
  }
}

static int is_fuzzing(void) {
  char *env_isfuzzing = getenv("FUZZ_ISFUZZING");
  if(env_isfuzzing && atoi(env_isfuzzing) == 1) {
    return 1;
  }
  return 0;
}

#define AFL_INIT_ARGV()          \
  do {                           \
                                 \
    argv = afl_init_argv(&argc); \
    \
  } while (0)

#define AFL_INIT_SET0(_p)        \
  do {                           \
    \
    argv = afl_init_argv(&argc); \
    argv[0] = (_p);              \
    if (!argc) argc = 1;         \
    \
  } while (0)

#define MAX_CMDLINE_LEN 100000
#define MAX_CMDLINE_PAR 50000

static int target_has_file_input(void) {
  char *env_has_file_input = getenv("FUZZ_HAS_FILE_INPUT");
  if(env_has_file_input && env_has_file_input[0] == '1') {
    dprint(stdout, "ARG Target has file input\n");
    return 1;
  }
  return 0;
}

static int read_one(char *out, int fd, size_t max) {
  size_t len = 0;
  int nr = 0;
  do {
    nr = read(fd, out+len, 1);
    len += nr;
  } while(nr && *(out+len-nr) && len < max);
  return len;
}

static void afl_init_env(int fd) {
  int env_n = 0;
  char fuzz_env_val[256];
  char *env_val_ptr;
  char in_buf[FUZZ_ARGV_BUF_LEN];
  memset(in_buf, 0, FUZZ_ARGV_BUF_LEN);

  env_val_ptr = getenv("ENV_FUZZ_COUNT");
  if(!env_val_ptr) {
    fprintf(stderr, "ENV Warning no ENV_FUZZ_COUNT\n");
    return;
  }
  env_n = atoi(env_val_ptr);
  dprint(stdout, "ENV fuzzing %d env variables\n", env_n);

  for(int i=0; i<env_n; i++) {
    snprintf(fuzz_env_val, 256, "ENV_FUZZ_COUNT_%d", i);
    dprint(stdout, "ENV Loading %d %s\n", i, fuzz_env_val);
    env_val_ptr = getenv(fuzz_env_val);
    if(!env_val_ptr) {
      fprintf(stderr, "ENV Warning no %s\n", fuzz_env_val);
      continue;
    }
    dprint(stdout, "ENV Fuzzing env var %s\n", env_val_ptr);
    if(read_one(in_buf, fd, FUZZ_ARGV_BUF_LEN) == 0) {
      fprintf(stderr, "ENV no more input\n");
      return;
    }
    if(in_buf[0] == 0x02 && in_buf[1] == 0) {
      dprint(stdout, "ENV Unset %s\n", env_val_ptr);
      unsetenv(env_val_ptr);
    } else {
      setenv(env_val_ptr, in_buf, 1);
      dprint(stdout, "Env loaded val %s: %s\n", env_val_ptr, getenv(env_val_ptr));
    }
  }
}

static char **afl_init_argv(int *argc) {
  static char *ret[MAX_CMDLINE_PAR];
  static char in_buf[FUZZ_ARGV_BUF_LEN];

  int has_file_input = 0;
  int rc = 0;
  char *ptr = in_buf;
  int arglen = 0;
  int total_len = 0;

  check_debug();

  has_file_input = target_has_file_input();
  afl_init_env(0);
  memset(in_buf, 0, FUZZ_ARGV_BUF_LEN);

  while(rc < MAX_CMDLINE_PAR) {
    arglen = read_one(ptr, 0, FUZZ_ARGV_BUF_LEN - total_len);
    if(arglen==0) {
      fprintf(stderr, "ARG no more input\n");
      break;
    }
    dprint(stdout, "ARG read argv[%d]: %s\n", rc, ptr);
    ret[rc] = ptr;
    ptr += arglen;
    total_len += arglen;
    if (has_file_input && ret[rc][0] == '-' && !ret[rc][1]) {
      dprint(stdout, "ARG stdin input starting at argv[%d]\n", rc-1);
      rc++;
      break;
    }
    rc++;
  }

  *argc = rc;

  for(int i=0;(int)i<*argc;i++) {
    dprint(stdout, "ARG load argv[%d]: %s\n", i, ret[i]);
  }
  return ret;
}

static void afl_dump_argv(int argc, char** argv, int dump_fd) {
  char buf[MAX_CMDLINE_LEN];
  int stdin_fd = 0;
  int len = 0;
  int has_file_input = 0;
  int i = 0;

  if(dump_fd<0) {
    fprintf(stderr, "DMP no dump fd (%d)\n", dump_fd);
  }
  for(i=0; (int)i<argc; i++) {
    dprint(stdout, "DMP argv[%d]: %s\n", (int)i, argv[i]);
  }
  has_file_input = target_has_file_input();
  for(i=0; i<argc; i++) {
    if (has_file_input && i>0 && (int)i==argc-1 && access(argv[i], F_OK) == 0) {
      dprint(stdout, "DMP Detected last file argument at %d: %s\n", argc, argv[i]);
      stdin_fd = open(argv[i], O_RDONLY);
      if(stdin_fd) {
	write(dump_fd, "-", 2);
	len = read(stdin_fd, buf, MAX_CMDLINE_LEN);
	dprint(stdout, "DMP Added %d bytes of fake stdin\n", len);
	write(dump_fd, buf, len);
	close(stdin_fd);
      }
    } else {
      write(dump_fd, argv[i], strlen(argv[i])+1);
    }
  }
}

#undef MAX_CMDLINE_LEN
#undef MAX_CMDLINE_PAR

#endif                                              /* !_HAVE_ARGV_FUZZ_INL */

