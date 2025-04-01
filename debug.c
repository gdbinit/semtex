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
#include "debug.h"

void print_x64_registers(uc_engine *uc)
{
    x86_thread_state64_t thread_state = {0};
    if (get_x64_registers(uc, &thread_state) != 0) {
        ERROR_MSG("Can't retrieve x86_64 registers.");
        return;
    }
    OUTPUT_MSG(SEPARATOR_COLOR "-----------------------------------------------------------------------------------------------------------------------[regs]" ANSI_COLOR_RESET);
    fprintf(stdout, REGISTER_COLOR "  RAX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RBX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RBP:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RSP:" ANSI_COLOR_RESET " 0x%016llx  " EFLAGS_COLOR, thread_state.__rax, thread_state.__rbx, thread_state.__rbp, thread_state.__rsp);
    (thread_state.__rflags >> 0xB) & 1 ? printf("O ") : printf("o ");
    (thread_state.__rflags >> 0xA) & 1 ? printf("D ") : printf("d ");
    (thread_state.__rflags >> 0x9) & 1 ? printf("I ") : printf("i ");
    (thread_state.__rflags >> 0x8) & 1 ? printf("T ") : printf("t ");
    (thread_state.__rflags >> 0x7) & 1 ? printf("S ") : printf("s ");
    (thread_state.__rflags >> 0x6) & 1 ? printf("Z ") : printf("z ");
    (thread_state.__rflags >> 0x4) & 1 ? printf("A ") : printf("a ");
    (thread_state.__rflags >> 0x2) & 1 ? printf("P ") : printf("p ");
    (thread_state.__rflags) & 1 ? printf("C ") : printf("c ");
    fprintf(stdout, "\n" ANSI_COLOR_RESET);
    OUTPUT_MSG(REGISTER_COLOR "  RDI:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RSI:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RDX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RCX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RIP:" ANSI_COLOR_RESET " 0x%016llx", thread_state.__rdi, thread_state.__rsi, thread_state.__rdx, thread_state.__rcx, thread_state.__rip);
    OUTPUT_MSG(REGISTER_COLOR "  R8 :" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R9 :" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R10:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R11:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R12:" ANSI_COLOR_RESET " 0x%016llx", thread_state.__r8, thread_state.__r9, thread_state.__r10, thread_state.__r11, thread_state.__r12);
    OUTPUT_MSG(REGISTER_COLOR "  R13:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R14:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R15:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "EFLAGS:" ANSI_COLOR_RESET " 0x%016llx", thread_state.__r13, thread_state.__r14, thread_state.__r15, thread_state.__rflags);
    OUTPUT_MSG(SEPARATOR_COLOR "-----------------------------------------------------------------------------------------------------------------------------" ANSI_COLOR_RESET);
}

void print_stack(uc_engine *uc) 
{
    uint64_t rsp = 0;
    uc_err err = 0;
    err = uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to read stack register.");
        return;
    }
    uint64_t stack_buf[16] = {0};
    for (int i = 0; i < 16; i++) {
        err = uc_mem_read(uc, rsp, &stack_buf[i], sizeof(uint64_t));
        OUTPUT_MSG("0x%llx | %llx", rsp, stack_buf[i]);
        rsp += sizeof(rsp);
    }
}
