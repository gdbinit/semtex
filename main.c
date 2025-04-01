/*
 *   _________               __                 
 *  /   _____/ ____   ______/  |_  ____ ___  ___
 *  \_____  \_/ __ \ /     \   __\/ __ \\  \/  /
 *  /        \  ___/|  Y Y  \  | \  ___/ >    < 
 * /_______  /\___  >__|_|  /__|  \___  >__/\_ \
 *         \/     \/      \/          \/      \/ 🧨 
 *
 * A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 *
 * Created by fG! on 08/03/2025.
 * (c) fG!, 2025 - reverser@put.as - https://reverse.put.as
 *
 * This program is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Tested with Apple Silicon macOS, might build and run in Linux :P
 *
 * https://reverse.put.as/2025/03/13/cracking-the-crackers/
 *
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unicorn/unicorn.h>
#include "hooks.h"
#include "log.h"
#include "config.h"
#include "registers.h"
#include "debug.h"
#include "macho.h"

// a simple helper function to map and set the initial stack and registers state
int map_stack_and_initial_registers(uc_engine *uc)
{
    DEBUG_MSG("Mapping initial registers...");
    uc_err err = UC_ERR_OK;    
    // map stack area
    err = uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to allocate Unicorn stack memory area: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }

    unsigned char *zero = calloc(1, STACK_SIZE);
    err = uc_mem_write(uc, STACK_ADDRESS, zero, STACK_SIZE);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to zero stack memory.");
        free(zero);
        uc_close(uc);
        return -1;
    }
    free(zero);

    int x86_64_regs[] = {
        UC_X86_REG_RIP,
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP,
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
        UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10,
        UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
        UC_X86_REG_R15, UC_X86_REG_CS,  UC_X86_REG_FS,  UC_X86_REG_GS, UC_X86_REG_EFLAGS
    };
    uint64_t vals[sizeof(x86_64_regs)] = {0};
    void *ptrs[sizeof(x86_64_regs)] = {0};
    for (int i = 0; i < sizeof(x86_64_regs); i++) {
        ptrs[i] = &vals[i];
    }
    err = uc_reg_write_batch(uc, x86_64_regs, ptrs, sizeof(x86_64_regs));
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to initialize all registers: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    // set initial stack pointer halfway the available stack space
    uint64_t r_rsp = STACK_ADDRESS + STACK_SIZE / 2;
    err = uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to write initial RSP register: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    DEBUG_MSG("Wrote initial RSP as 0x%llx", r_rsp);
    err = uc_reg_write(uc, UC_X86_REG_RBP, &r_rsp);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to write initial RBP register: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    return 0;
}

// helper function to map whatever code we want at the configured address
int map_target(uc_engine *uc, void *target_buf, size_t target_size)
{
    DEBUG_MSG("Mapping the code...");
    uc_err err = UC_ERR_OK;
    // allocate Unicorn code area
    err = uc_mem_map(uc, CODE_ADDRESS, CODE_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to allocate Unicorn code memory area: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    // map the target
    err = uc_mem_write(uc, CODE_ADDRESS, target_buf, target_size);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to write target to Unicorn memory: %s", uc_strerror(err));
        return -1;
    }
    // if we need we can patch code memory here :-)

    // some debugging info 
    DEBUG_MSG("Target code area:");
    char dbg_buf[64] = {0};
    uc_mem_read(uc, CODE_ADDRESS, dbg_buf, 64);
    for (int i = 0; i < sizeof(dbg_buf) ; i++) {
        if (i && i % 16 == 0) { printf("\n"); };
        printf("%02x ", (unsigned char)dbg_buf[i]);
    }
    printf("\n");    
    return 0;
}

int start_emulation(unsigned char *target_buf, size_t target_size, struct user_data *udata, char *outputfile)
{
    OUTPUT_MSG("\nLet's start the partyyyyyyyyyy 🥳\n");
    uc_engine *uc = NULL;        
    uc_err err = UC_ERR_OK;
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to open Unicorn: %s.", uc_strerror(err));
        return -1;
    }
    if (map_stack_and_initial_registers(uc) != 0) {
        ERROR_MSG("Failed to map initial stack and registers.");
        uc_close(uc);
        return -1;
    }
    if (map_target(uc, target_buf, target_size) != 0) {
        ERROR_MSG("Failed to map target.");
        uc_close(uc);
        return -1;
    }
    // code trace hook - used to intercept the symbol stubs
    // this will be slower since we trace every executed instruction
    // but if we don't flood output it's pretty fast on a modern CPU
    uc_hook trace_hook;
    if (uc_hook_add(uc, &trace_hook, UC_HOOK_CODE | UC_HOOK_INSN_INVALID, unicorn_hook_code, (void*)udata, 1, 0) != UC_ERR_OK) {
        ERROR_MSG("Failed to set code hook");
    }
    // hook to detect unmapped memory issues - useful when developing
    uc_hook mem_hook;
    if (uc_hook_add(uc, &mem_hook, UC_HOOK_MEM_UNMAPPED, unicorn_hook_unmapped_mem, NULL, 1, 0) != UC_ERR_OK) {
        ERROR_MSG("Failed to set memory hook");
    }

    DEBUG_MSG("Initial register state:");
    print_x64_registers(uc);

    // start the party :-]
    uint64_t start_address = CODE_ADDRESS + udata->load_method;
    err = uc_emu_start(uc, start_address, start_address + target_size, 0, 0);    
    // emulation has stopped - so we can use this to dump the decrypted code from Unicorn memory
    if (outputfile != NULL) {
        OUTPUT_MSG("=> Dumping the decrypted code...");
        char *output_buf = malloc(target_size);
        if (uc_mem_read(uc, CODE_ADDRESS, output_buf, target_size) != UC_ERR_OK) {
            ERROR_MSG("Failed to read data for dumping.");
            return -1;
        }
#if 0
        for (int i = 0; i < 256 ; i++) {
            if (i && i % 16 == 0) { printf("\n"); };
            printf("%02x ", (unsigned char)output_buf[i]);
        }
        printf("\n");
#endif
        int out_fd = open(outputfile, O_RDWR | O_CREAT, 0644);
        if (out_fd < 0) {
            ERROR_MSG("Failed to create file");
            return -1;
        }
        write(out_fd, output_buf, target_size);
        close(out_fd);
        OUTPUT_MSG("[+] Decrypted library to %s", outputfile);
    }
    // now we can finally cleanup
    DEBUG_MSG("Execution return value: %d (%s)", err, uc_strerror(err));    
    uc_close(uc);
    OUTPUT_MSG("[+] All done! Thank you for using semtex.");
    return 0;
}

int read_file(char *path, unsigned char**buf, size_t *size) 
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        ERROR_MSG("Failed to open %s.", path);
        return 1;
    }
    struct stat fs = {0};
    if (fstat(fd, &fs) < 0) {
        ERROR_MSG("Failed to fstat %s.", path);
        close(fd);
        return 1;
    }
    *buf = calloc(1, fs.st_size);
    if (*buf == NULL) {
        ERROR_MSG("Malloc failure.");
        close(fd);
        return 1;
    }
    if (read(fd, *buf, fs.st_size) != fs.st_size) {
        ERROR_MSG("Failed to read %s.", path);
        free(*buf);
        *buf = NULL;
        close(fd);
        return 1;
    }
    *size = fs.st_size;
    close(fd);
    return 0;
}

void header(void)
{
    OUTPUT_MSG("  _________               __                 ");
    OUTPUT_MSG(" /   _____/ ____   ______/  |_  ____ ___  ___");
    OUTPUT_MSG(" \\_____  \\_/ __ \\ /     \\   __\\/ __ \\   \\/  /");
    OUTPUT_MSG(" /        \\  ___/|  Y Y  \\  | \\  ___/ >    < ");
    OUTPUT_MSG("/_______  /\\___  >__|_|  /__|  \\___  >__/\\_ \\");
    OUTPUT_MSG("        \\/     \\/      \\/          \\/      \\/");
    OUTPUT_MSG("     (c) fG!, 2025, All rights reserved.");
    OUTPUT_MSG("   reverser@put.as - https://reverse.put.as");
    OUTPUT_MSG("---------------------------------------------");
    OUTPUT_MSG("");
}

void help(const char *name)
{
    header();
    printf(
           "Usage: %s -i <input filename> [-o <output filename>] [-h]\n\n"
           "Command options:\n"
           "  -i, --input value       TNT crack dylib to load\n"
           "  -o, --output value      Output file for the dumped code [optional]"
           "\n", name);
}

int main(int argc, const char * argv[])
{
    // required structure for long options
    static struct option long_options[]={
        { "input", required_argument, NULL, 'i' },
        { "output", required_argument, NULL, 'o' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    int option_index = 0;
    int c = 0;

    char *inputfile = NULL;
    char *outputfile = NULL;
    
    // process command line options
    while ((c = getopt_long (argc, (char * const*)argv, "hi:o:", long_options, &option_index)) != -1)
    {
        switch (c)
        {
            case 'i':
                inputfile = optarg;
                break;
            case 'o':
                outputfile = optarg;
                break;
            case 'h':
                help(argv[0]);
                exit(0);
            default:
                break;
        }
    }
    
    if (inputfile == NULL) {
        ERROR_MSG("Missing argument!");
        help(argv[0]);
        exit(1);
    }

    unsigned char *target_buf = NULL;
    size_t target_size = 0;

    if (read_file(inputfile, &target_buf, &target_size)) {
        exit(1);
    }

    header();

    DEBUG_MSG("Target size is %zu bytes.", target_size);
    struct user_data udata = {0};

    if (parse_macho(target_buf, target_size, &udata) < 0) {
        ERROR_MSG("Failed to parse target binary.");
        return 1;
    }

    start_emulation(target_buf, target_size, &udata, outputfile);

    return 0;
}
