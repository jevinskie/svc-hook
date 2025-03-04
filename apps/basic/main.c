// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 Akira Moroo

#include <stdint.h>
#include <stdio.h>

typedef uintptr_t (*syscall_fn_t)(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
                                  uintptr_t, uintptr_t, uintptr_t, uintptr_t);

static syscall_fn_t next_sys_call = NULL;

static uintptr_t hook_function(uintptr_t a1, uintptr_t a2, uintptr_t a3,
                               uintptr_t a4, uintptr_t a5, uintptr_t a6,
                               uintptr_t a7, uintptr_t a8) {
  printf("output from hook_function: syscall number %ld\n", a7);
  fflush(stdout);
  return next_sys_call(a1, a2, a3, a4, a5, a6, a7, a8);
}

int __hook_init(uintptr_t placeholder __attribute__((unused)),
                void *sys_call_hook_ptr) {
  printf("output from __hook_init: we can do some init work here\n");
  fflush(stdout);

  next_sys_call = *((syscall_fn_t *)sys_call_hook_ptr);
  *((syscall_fn_t *)sys_call_hook_ptr) = hook_function;

  return 0;
}
