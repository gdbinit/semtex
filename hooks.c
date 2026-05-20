/*
 *
 * 🧨 semtex - A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 * (c) fG!, 2025-2026 - reverser@put.as - https://reverse.put.as
 *
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <inttypes.h>
#include <unicorn/unicorn.h>
#include "hooks.h"
#include "log.h"
#include "config.h"
#include "registers.h"
#include "debug.h"
#include "disasm.h"

extern int verbose;

uc_hook *memwrite_hook;
uint64_t min_addr = UINT64_MAX;
uint64_t max_addr = 0;

void hexdump(unsigned char *buf, size_t len, uint64_t addr) {
    /* output data in hex and characters if possible */
    uint64_t i = 0;
    uint64_t x = 0;
    uint64_t z = 0;
    uint64_t linelength = 0;
    fprintf(stdout, "-[Buffer size: %ld ]-------------------\n", len);
    while (i < len) {
        linelength = (len - i) <= 16 ? len - i : 16;
        z = i;
        fprintf(stdout, "0x%08" PRIx64 ": ", addr);
        addr += 16;
        for (x = 0; x < linelength; x++) {
            fprintf(stdout, "%02X ", buf[z++]);
        }
        // make it always 16 columns, this could be prettier :P
        for (x = linelength; x < 16; x++) {
            fprintf(stdout, "   ");
        }
        z = i;
        // try to print ascii
        fprintf(stdout, "|");
        for (x = 0; x < linelength; x++) {
            fprintf(stdout, "%c", isascii(buf[z]) && isprint(buf[z]) ? buf[z] : '.');
            z++;
        }
        i += 16;
        fprintf(stdout, "|\n");
    }
}

// the code hook can be used to trace every instruction executed
void unicorn_hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    if (verbose >= 2) {
        DEBUG_MSG("Hit code at 0x%" PRIx64, address);
    }
    struct user_data *udata = (struct user_data*)user_data;

    int arg_reg[] = {
            UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9,
    };
    uint64_t arg_val[sizeof(arg_reg)/sizeof(*arg_reg)] = {0};
    void *arg_ptr[sizeof(arg_reg)/sizeof(*arg_reg)] = {0};

    // mprotect call
    // int mprotect(void *addr, size_t len, int prot);
    if (address == CODE_ADDRESS + udata->mprotect_stub) {
        for (int i = 0; i < sizeof(arg_reg)/sizeof(*arg_reg); i++) {
            arg_ptr[i] = &arg_val[i];
        }
        if (uc_reg_read_batch(uc, arg_reg, arg_ptr, sizeof(arg_reg)/sizeof(*arg_reg)) != UC_ERR_OK) {
            ERROR_MSG("Failed to batch read mprotect() arguments registers.");
            return;
        }
        uint64_t param_addr = (uint64_t)arg_val[0];
        size_t param_len = (size_t)arg_val[1];
        int param_prot = (int)arg_val[2];
        OUTPUT_MSG("\n* 0x%"PRIx64" - mprotect(0x%"PRIx64", 0x%zx, %d)", address, param_addr, param_len, param_prot);

        // reset previous hook if set
        if (memwrite_hook != NULL) {
            DEBUG_MSG("Previous min: 0x%"PRIx64" max: 0x%"PRIx64, min_addr, max_addr);
            uc_hook_del(uc, *memwrite_hook);
            free(memwrite_hook);
            memwrite_hook = NULL;
            min_addr = UINT64_MAX;
            max_addr = 0;
        }
    
        // enable hook to detect memory writes - aka the decryption
        memwrite_hook = malloc(sizeof(uc_hook));
        if (uc_hook_add(uc, memwrite_hook, UC_HOOK_MEM_WRITE, unicorn_hook_write_mem, NULL, CODE_ADDRESS + param_addr , CODE_ADDRESS + param_addr + param_len) != UC_ERR_OK) {
            ERROR_MSG("Failed to set memory hook");
        }

        // return 0
        uint64_t reg_rax = 0;
        if (uc_reg_write(uc, UC_X86_REG_RAX, &reg_rax) != UC_ERR_OK) {
            ERROR_MSG("Failed to write mprotect() return value");
            return;
        }
        // return to caller
        uint64_t rsp = 0;
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
        uint64_t ret = 0;
        uc_mem_read(uc, rsp, &ret, sizeof(ret));
        DEBUG_MSG("Return address is 0x%" PRIx64, ret);
        uint64_t rip = ret;
        if (uc_reg_write(uc, UC_X86_REG_RIP, &rip) != UC_ERR_OK) {
            ERROR_MSG("Failed to advance RIP");
            return;
        }
        return;
    }

    // _dyld_get_image_vmaddr_slide
    // intptr_t _dyld_get_image_vmaddr_slide(uint32_t image_index)
    // this is the stub address
    if (address == CODE_ADDRESS + udata->dyld_get_slide_stub) {
        DEBUG_MSG("Previous min: 0x%" PRIx64 " max: 0x%" PRIx64, min_addr, max_addr);
        for (int i = 0; i < sizeof(arg_reg)/sizeof(*arg_reg); i++) {
            arg_ptr[i] = &arg_val[i];
        }
        if (uc_reg_read_batch(uc, arg_reg, arg_ptr, sizeof(arg_reg)/sizeof(*arg_reg)) != UC_ERR_OK) {
            ERROR_MSG("Failed to batch read mprotect() arguments registers.");
            return;
        }
        OUTPUT_MSG("\n* 0x%" PRIx64 " - _dyld_get_image_vmaddr_slide(%u)", address, (uint32_t)arg_val[0]);
        // return a value different than zero to bypass the anti-debugging check
        // it's unused so anything different than zero works
        uint64_t reg_rax = 0x1;
        if (uc_reg_write(uc, UC_X86_REG_RAX, &reg_rax) != UC_ERR_OK) {
            ERROR_MSG("Failed to write mprotect() return value");
            return;
        }
        // return to caller
        uint64_t rsp = 0;
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
        uint64_t ret = 0;
        uc_mem_read(uc, rsp, &ret, sizeof(ret));
        DEBUG_MSG("Return address is 0x%" PRIx64, ret);
        uint64_t rip = ret;
        if (uc_reg_write(uc, UC_X86_REG_RIP, &rip) != UC_ERR_OK) {
            ERROR_MSG("Failed to advance RIP");
            return;
        }
        return;
    }
}

// the hook we use to detect when unmapped memory is hit
// very useful when developing
bool unicorn_hook_unmapped_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    uint64_t reg_eip = 0;
    if (uc_reg_read(uc, UC_X86_REG_RIP, &reg_eip) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read RIP");
        return false;
    }
    DEBUG_MSG("Memory exception at 0x%" PRIx64, reg_eip);
    DEBUG_MSG("Unmapped mem hit 0x%" PRIx64, address);
    print_x64_registers(uc);
    print_stack(uc);
    return false;
}

// used to detect where memory is being written so we can track the decryption addresses
bool unicorn_hook_write_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    if (verbose) {
        DEBUG_MSG("Hit memory write at 0x%" PRIx64 " of %d byte(s): 0x%" PRIx64, address, size, value);    
    }   
    if (address < min_addr) min_addr = address;
    if (address > max_addr) max_addr = address;
    return true;
}
