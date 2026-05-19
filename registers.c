/*
 *
 * 🧨 semtex - A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 * (c) fG!, 2025 - reverser@put.as - https://reverse.put.as
 *
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unicorn/unicorn.h>

#include "log.h"
#include "registers.h"

int get_x64_registers(uc_engine *uc, x86_thread_state64_t *state)
{
    if (uc == NULL || state == NULL) {
        ERROR_MSG("Invalid arguments.");
        return -1;
    }
    
    int x86_64_regs[] = {
        UC_X86_REG_RIP,
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
        UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
        UC_X86_REG_R15, UC_X86_REG_CS, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_EFLAGS
    };
    uint64_t vals[sizeof(x86_64_regs)/sizeof(*x86_64_regs)] = {0};
    void *ptrs[sizeof(x86_64_regs)/sizeof(*x86_64_regs)] = {0};
    
    for (int i = 0; i < sizeof(x86_64_regs)/sizeof(*x86_64_regs); i++) {
        ptrs[i] = &vals[i];
    }
    
    if (uc_reg_read_batch(uc, x86_64_regs, ptrs, sizeof(x86_64_regs)/sizeof(*x86_64_regs)) != UC_ERR_OK) {
        ERROR_MSG("Failed to read x64 general registers.");
        return -1;
    }
    
    state->__rip = vals[0];
    state->__rax = vals[1];
    state->__rbx = vals[2];
    state->__rbp = vals[3];
    state->__rsp = vals[4];
    state->__rdi = vals[5];
    state->__rsi = vals[6];
    state->__rdx = vals[7];
    state->__rcx = vals[8];
    state->__r8  = vals[9];
    state->__r9  = vals[10];
    state->__r10 = vals[11];
    state->__r11 = vals[12];
    state->__r12 = vals[13];
    state->__r13 = vals[14];
    state->__r14 = vals[15];
    state->__r15 = vals[16];
    state->__cs  = vals[17];
    state->__fs  = vals[18];
    state->__cs  = vals[19];
    state->__rflags = vals[20];    
    return 0;
}
