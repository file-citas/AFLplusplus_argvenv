/*
   american fuzzy lop++ - LD_PRELOAD for fuzzing argv in binaries
   ------------------------------------------------------------

   Copyright 2019-2022 Kjell Braden <afflux@pentabarf.de>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#define _GNU_SOURCE                                        /* for RTLD_NEXT */
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "argv-fuzz-inl.h"

static char env_filename[PATH_MAX] = {0};
static char arg_filename[PATH_MAX] = {0};
static char base_filename[PATH_MAX] = {0};

static char *generate_base_filename(void) {
  if(base_filename[0] != 0) {
    return base_filename;
  }
  uuid_t binuuid;
  char uuid[64];
  char *output_base_dir = getenv("FUZZ_OUTPUT_BASE");
  if(!output_base_dir) {
    fprintf(stderr, "Need FUZZ_OUTPUT_BASE!\n");
    exit(EXIT_FAILURE);
  }
  char *output_base_prog = getenv("FUZZ_I_BASEPROG");
  if(!output_base_prog) {
    fprintf(stderr, "Need FUZZ_OUTPUT_BASE!\n");
    exit(EXIT_FAILURE);
  }
  uuid_generate(binuuid);
  uuid_unparse_upper(binuuid, uuid);
  snprintf(base_filename, PATH_MAX, "%s/fuzzi_%s_%s", output_base_dir, output_base_prog, uuid);
  return base_filename;
}

static int is_fuzz_env(const char *name) {
  if(strcmp(name, "FUZZ_OUTPUT_BASE") == 0) {
    return 1;
  } else if(strcmp(name, "FUZZ_I_BASEPROG") == 0) {
    return 1;
  } else if(strcmp(name, "LD_PRELOAD") == 0) {
    return 1;
  } else if(strcmp(name, "FUZZ_HAS_FILE_INPUT") == 0) {
    return 1;
  } else if(strcmp(name, "ENV_FUZZ_COUNT") == 0) {
    return 1;
  } else if(strcmp(name, "FUZZ_HAS_FILE_INPUT") == 0) {
    return 1;
  }
  return 0;
}

char* getenv(const char *name) {
  char* (*orig)(const char *name);
  orig = dlsym(RTLD_NEXT, __func__);

  if (!orig) {
    fprintf(stderr, "hook did not find original %s: %s\n", __func__, dlerror());
    exit(EXIT_FAILURE);

  }
  if(is_fuzz_env(name)) {
    return orig(name);
  }

  if(env_filename[0] == 0) {
    snprintf(env_filename, PATH_MAX, "%s.env", generate_base_filename());
  }

  char *envval = orig(name);
  dprint(stdout, "ENV dumping to %s\n", env_filename);
  FILE *env_dump = fopen(env_filename, "at");
  if(!env_dump) env_dump = fopen(env_filename, "wt");
  if(!env_dump) {
    fprintf(stderr, "ENV failed to open %s\n", env_filename);
    exit(EXIT_FAILURE);
  } else {
    fprintf(env_dump, "%s: %s\n", name, envval);
    fclose(env_dump);
  }
  return (char*)envval;
}

int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv,
                      void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end) {

  int (*orig)(int (*main)(int, char **, char **), int argc, char **argv,
              void (*init)(void), void (*fini)(void), void (*rtld_fini)(void),
              void *stack_end);
  orig = dlsym(RTLD_NEXT, __func__);

  if (!orig) {
    fprintf(stderr, "hook did not find original %s: %s\n", __func__, dlerror());
    exit(EXIT_FAILURE);
  }

  if(arg_filename[0] == 0) {
    snprintf(arg_filename, PATH_MAX, "%s.arg", generate_base_filename());
  }
  int dump_fd = open(arg_filename, O_CREAT | O_RDWR, 0666);
  if(dump_fd < 0) {
    fprintf(stderr, "ARG failed to open %s\n", arg_filename);
    exit(EXIT_FAILURE);
  }
  afl_dump_argv(argc, argv, dump_fd);
  close(dump_fd);

  return orig(main, argc, argv, init, fini, rtld_fini, stack_end);

}

