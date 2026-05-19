/*
 *
 * 🧨 semtex - A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 * (c) fG!, 2025-2026 - reverser@put.as - https://reverse.put.as
 *
 */

#pragma once

#include <stdint.h>
#include <unicorn/unicorn.h>

// redefine this structure because depends on target build arch if we use the system includes
// plus it wasn't portable...
typedef struct x86_thread_state64 {
    uint64_t    __rax;
    uint64_t    __rbx;
    uint64_t    __rcx;
    uint64_t    __rdx;
    uint64_t    __rdi;
    uint64_t    __rsi;
    uint64_t    __rbp;
    uint64_t    __rsp;
    uint64_t    __r8;
    uint64_t    __r9;
    uint64_t    __r10;
    uint64_t    __r11;
    uint64_t    __r12;
    uint64_t    __r13;
    uint64_t    __r14;
    uint64_t    __r15;
    uint64_t    __rip;
    uint64_t    __rflags;
    uint64_t    __cs;
    uint64_t    __fs;
    uint64_t    __gs;
} x86_thread_state64_t;

int get_x64_registers(uc_engine *uc, x86_thread_state64_t *state);
