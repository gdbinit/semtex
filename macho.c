/*
 *
 * 🧨 semtex - A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 * (c) fG!, 2025-2026 - reverser@put.as - https://reverse.put.as
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "macho.h"
#include "log.h"
#include "Zydis.h"
#include "hooks.h"
#include "objc.h"

static uint64_t decode_uleb128(uint8_t *buf, size_t *offset) 
{
    uint64_t result = 0;
    int bit = 0;
    do {
        uint64_t slice = *buf & 0x7F;
        if (bit >= 64 || slice << bit >> bit != slice) {
            ERROR_MSG("something is broken!");
        } else {
            result |= (slice << bit);
            bit += 7;
            *offset += 1;
        }
    } while (*buf++ & 0x80);
    return result;
}

// a big function parsing mach-o target to find the symbol locations and other information we need
int parse_macho(unsigned char *buf, size_t buf_size, struct user_data *udata) 
{
    if (buf_size < sizeof(struct mach_header_64)) {
        ERROR_MSG("Buffer is too small.");
        return -1;
    }
    // ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️
    // this is very much PoC code without bounds check etc in general
    // just to showcase the ideas not production level code (use AI for that, LOL)
    // C forever 🤘🤘🤘
    // ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️
    uint32_t magic = *(uint32_t*)buf;
    if (magic != MH_MAGIC_64) {
        ERROR_MSG("Only 64 bit non-fat binary supported.");
        return -1;
    }

    struct mach_header_64 *mh = (struct mach_header_64*)buf;
    if (mh->cputype != CPU_TYPE_X86_64) {
        ERROR_MSG("Only x86_64 target supported.");
        return -1;
    }

    // parse the mach-o to find the information we need
    // most segment commands and sections have names and/or information obfuscated
    // so we locate them using flags and other unique features

    struct dyld_info_command *dic = NULL;
    size_t max_segments = 8;
    struct segment_command_64 *segments = calloc(max_segments, sizeof(struct segment_command_64));
    size_t segment_index = 0;
    struct section_64 *stubs = NULL;
    struct section_64 *objc_const = NULL;
    struct section_64 *objc_data = NULL;
    struct section_64 *lazy_sym = NULL;
    struct segment_command_64 *linkedit = NULL;
    struct symtab_command *symtab = NULL;
    struct dysymtab_command *dsymtab = NULL;

    struct load_command *lc = (struct load_command*)(buf + sizeof(struct mach_header_64));
    for (size_t i = 0; i < mh->ncmds; i++) {
        switch (lc->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *sg = (struct segment_command_64*)lc;
                // add our copy
                if (segment_index < max_segments) {
                    segments[segment_index++] = *sg;    
                }
                
                // name is mangled so try to use the EXECUTE protection to distinguish the segment
                // XXX: got confused with the section since segment name is not obfuscated
                //      anyway let it stay this way unless it breaks in the future :P
                if ((sg->maxprot & VM_PROT_EXECUTE) && (sg->initprot & VM_PROT_EXECUTE)) {
                    struct section_64 *sc = (struct section_64*)((char*)sg + sizeof(struct segment_command_64));
                    for (size_t x = 0; x < sg->nsects; x++) {
                        // this gives us the location of the jump stubs for lazy symbols
                        // the symbols are obfuscated so we can't use the symbol table to find them
                        // but the info still exists in LC_DYLD_INFO[_ONLY]
                        // we have the pointers there so we can link that info with info here
                        // and find which is what
                        if ((sc->flags & SECTION_TYPE) == S_SYMBOL_STUBS) {
                            // DEBUG_MSG("Found STUBS: 0x%" PRIx64, sc->addr);
                            stubs = sc;
                            break;
                        }
                        sc = (struct section_64*)((char*)sc + sizeof(struct section_64));
                    }
                }
                // __DATA
                int32_t prot = VM_PROT_READ | VM_PROT_WRITE;
                if (sg->maxprot == prot && sg->initprot == prot) {
                    // we need __objc_const whic is not obfuscated
                    // probably because OBJC is picky about this
                    struct section_64 *sc = (struct section_64*)((char*)sg + sizeof(struct segment_command_64));
                    for (size_t x = 0; x < sg->nsects; x++) {
                        if (strncmp(sc->sectname, "__objc_const", sizeof(sc->sectname)) == 0) {
                            objc_const = sc;
                        } else if (strncmp(sc->sectname, "__objc_data", sizeof(sc->sectname)) == 0) {
                            objc_data = sc;
                        } else if ((sc->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
                            lazy_sym = sc;
                        }
                        sc = (struct section_64*)((char*)sc + sizeof(struct section_64));
                    }
                }
                if (strncmp(sg->segname, "__LINKEDIT", sizeof(sg->segname)) == 0) {
                    linkedit = sg;
                }
                break;
            }
            case LC_DYLD_INFO:
            case LC_DYLD_INFO_ONLY:
            {
                // DEBUG_MSG("Found LC_DYLD_INFO");
                dic = (struct dyld_info_command*)lc;
                break;
            }
            case LC_SYMTAB:
            {
                symtab = (struct symtab_command*)lc;
                break;
            }
            case LC_DYSYMTAB:
            {
                dsymtab = (struct dysymtab_command*)lc;
                break;
            }    
            default: 
                break;
            
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }

    if (dic == NULL) {
        ERROR_MSG("Missing LC_DYLD_INFO_ONLY command.");
        return -1;
    }

// this should be enough for all libraries?    
#define MAX_SYMBOLS 256
    struct oursym {
        char name[256]; // 256 chars ought to be enough for all symbols 💀
        uint64_t ptr;   // the symbol pointer address
        uint64_t stub;  // the symbol stub that uses above ptr to call the symbol
    };
    // should have been an hash table or something, but why bother with such small size?
    // KiSS is better and modern systems are fast :PPPP
    struct oursym *oursymtable = malloc(sizeof(struct oursym) * MAX_SYMBOLS);
    struct oursym *oursymtable_ptr = oursymtable;

    // now we can parse the DYLD information to locate the symbols we need
    // _mprotect and __dyld_get_image_vmaddr_slide
    // DEBUG_MSG("Lazy bind offset 0x%x with size 0x%x", dic->lazy_bind_off, dic->lazy_bind_size);
    uint8_t *ptr = buf + dic->lazy_bind_off;
    uint8_t *ptr_end = ptr + dic->lazy_bind_size;
    uint64_t mprotect_addr = 0;
    uint64_t dyld_get_image_vmaddr_slide_addr = 0;
    uint64_t cur_sym_addr = 0;
    // a very crude and ugly LC_DYLD_INFO_ONLY parser
    // we just need three opcodes anyway
    // it assumes that the opcodes are in an expected order
    // (which should be generally true...)
    OUTPUT_MSG("\n=> Parsing LC_DYLD_INFO_ONLY...");
    while (ptr < ptr_end) {
        uint8_t byte = *ptr++;
        uint8_t opcode = byte & BIND_OPCODE_MASK;
        uint8_t imm = byte & BIND_IMMEDIATE_MASK;
        switch (opcode) {
            // we need this opcode to find the base segment
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            {
                if (imm >= max_segments) {
                    ERROR_MSG("Segment index %d out of bounds!", imm);
                    return -1;
                }
                size_t offset = 0;
                uint64_t result = decode_uleb128(ptr, &offset);
                uint64_t seg_addr = segments[imm].vmaddr;
                // DEBUG_MSG("Value: 0x%" PRIx64, result + seg_addr);
                cur_sym_addr = result + seg_addr;
                ptr += offset;
                break;
            }
            // this will get us the symbol name
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            {
                char *string = (char*)ptr;
                if (strcmp(string, "_mprotect") == 0) {
                    mprotect_addr = cur_sym_addr;
                }
                if (strcmp(string, "__dyld_get_image_vmaddr_slide") == 0) {
                    dyld_get_image_vmaddr_slide_addr = cur_sym_addr;
                }
                OUTPUT_MSG("0x%08" PRIx64 " - %s", cur_sym_addr, string);
                oursymtable_ptr->ptr = cur_sym_addr;
                snprintf(oursymtable_ptr->name, 256, "%s", string);
                oursymtable_ptr->stub = 0;
                oursymtable_ptr++;
                ptr += strlen(string) + 1;
                break;
            }
            // now we should have everything we need from here
        case BIND_OPCODE_DO_BIND:
                cur_sym_addr = 0;
                break;
        default:
            break;
        }
    }
    OUTPUT_MSG("mprotect address: 0x%" PRIx64, mprotect_addr);
    OUTPUT_MSG("_dyld_get_image_vmaddr_slide address: 0x%" PRIx64, dyld_get_image_vmaddr_slide_addr);

    // now we need to disassemble the stubs section and find the locations with pointers
    // to the symbols we are interested in
    if (stubs == NULL) {
        ERROR_MSG("No __stubs section was found so we can't proceed.");
        return -1;
    }
    uint8_t *stubs_ptr = buf + stubs->offset;

    ZydisDecoder decoder = {0};
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZyanStatus status;
    ZydisDecodedInstruction inst;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];

    uint8_t *readPointer = stubs_ptr;
    size_t length = stubs->size;
    uint64_t ip = stubs->addr;
    OUTPUT_MSG("\n=> Locating original symbols...");
    while ((status = ZydisDecoderDecodeFull(&decoder, readPointer, length, &inst, ops)) != ZYDIS_STATUS_NO_MORE_DATA) {
            uint64_t jmp_addr = 0;
            if(!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &ops[0], ip, &jmp_addr))) {
                ERROR_MSG("Failed to compute jump target address");
                return -1;
            }
            if (jmp_addr == mprotect_addr) {
                OUTPUT_MSG("Found _mprotect stub at 0x%" PRIx64, ip);
                udata->mprotect_stub = ip;

            } else if (jmp_addr == dyld_get_image_vmaddr_slide_addr) {
                OUTPUT_MSG("Found __dyld_get_image_vmaddr_slide_addr stub at 0x%" PRIx64, ip);
                udata->dyld_get_slide_stub = ip;
            }
            // add the address to our table so we can correlate symbols
            for (int i = 0; i < MAX_SYMBOLS; i++) {
                // find the symbol that corresponds to this jump stub
                if (oursymtable[i].ptr == jmp_addr) {
                    // save the stub address so we can correlate when fixing the mangled symbol table
                    oursymtable[i].stub = ip;
                    break;
                }
            }
            readPointer += inst.length;
            length -= inst.length;
            ip += inst.length;
    }

    if (udata->mprotect_stub == 0 || udata->dyld_get_slide_stub == 0) {
        ERROR_MSG("Failed to locate required symbol stubs.");
        return -1;
    }

    // last step is to locate the +[LibraryLoad load] class method
    // which is the first code to be executed
    // we are lucky that Objective-C is more picky regarding obfuscation
    // so our life is a bit easier here (although we have to deal with obj-c internals)
    OUTPUT_MSG("\n=> Locating the load method...");
    // first we parse the info in __objc_data section
    // this will point us to the right structure inside __objc_const
    // we can't just parse __objc_const because that isn't sequential there
    // so the better way is to locate the right pointers and go from there

    // get a pointer to __objc_data section data
    uint8_t *objc_data_ptr = buf + objc_data->offset;
    // there are at least two structures in this section
    // the _OBJC_METACLASS_$_NSObject is the one that we are interested in
    // it will point to the struct __objc2_class_ro in __objc_const
    // that then points to the class methods, which is what we are looking for
    struct __objc2_class *class = (struct __objc2_class*)objc_data_ptr;
    DEBUG_MSG("Read-only class info at 0x%" PRIx64, (uint64_t)class->info);
    // let's treat it as an offset instead of virtual address
    size_t info_off = (uint64_t)class->info - objc_const->addr;
    
    // get pointer to the read-only class info structure inside __objc_const
    struct __objc2_class_ro *info = (struct __objc2_class_ro *)(buf + objc_const->offset + info_off);
    DEBUG_MSG("Methods array @ 0x%" PRIx64, (uint64_t)info->base_meths);
    // once again treat it as an offset
    size_t meths_off = (size_t)info->base_meths - objc_const->addr;
    // now we get the pointer to the "head" of the array
    struct __objc2_meth_list *ml = (struct __objc2_meth_list*)(buf + objc_const->offset + meths_off);
    // there should be only one method
    // this might be updated to break this code so manually check in disassembler if this fails
    if (ml->count != 1) {
        ERROR_MSG("More than one method defined, something might be wrong or changed.");
        return -1;
    }
    // and we can finally extract the method(s) address
    struct __objc2_meth *m = (struct __objc2_meth*)((char*)ml + sizeof(*ml));
    OUTPUT_MSG("load method implementation @ 0x%" PRIx64, (uint64_t)m->imp);
    udata->load_method = (uint64_t)m->imp;

    // fix symbols names just because we can 💪
    // we use the same information as above but this time we use LC_DYLD_INFO_ONLY
    // to locate the lazy symbols, find their strings and update with the original names
    // NOTE: we assume that there is space for the original string, which should be reasonable
    // because most probably the obfuscator works after the binary has been compiled and linked
    // hence the original names were already there
    OUTPUT_MSG("\n=> Fixing obfuscated symbol names...");
    struct nlist_64 *nlist = NULL;
    // DEBUG_MSG("Number of indirect syms: %u", dsymtab->nindirectsyms);
    // DEBUG_MSG("dysymtab offset: 0x%x", dsymtab->indirectsymoff);
    // DEBUG_MSG("Reserved: %d", lazy_sym->reserved1);
    // DEBUG_MSG("Lazy sym addr: 0x%" PRIx64, lazy_sym->addr);
    // 
    for (uint32_t i = 0; i < dsymtab->nindirectsyms; i++) {
        uint32_t index = *(uint32_t*)(buf + dsymtab->indirectsymoff + i * 4);
        // stop parsing when we hit this because it will switch to other types
        // and we don't care about those
        if (index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
            break;
        }
        // pointer to the nlist structure for this symbol
        // so we can finally get the obfuscated string pointer
        nlist = (struct nlist_64*)(buf + symtab->symoff + index * sizeof(struct nlist_64));
        char *sym = (char*)buf + symtab->stroff + nlist->n_un.n_strx;

        if (stubs->reserved2 == 0) {
            // XXX: set the value to sizeof(uint64_t)???
            ERROR_MSG("Stubs reserved2 field is zero! Don't know how to proceed.");
            return -1;
        }
        // finally we can compute the stub address for the current symbol
        uint64_t addr = stubs->addr + (i - stubs->reserved1) * stubs->reserved2;
        // try to locate the original symbol name in our own table
        // this might fail for some C++ symbols        
        for (int x = 0; x < MAX_SYMBOLS; x++) {
            if (oursymtable[x].stub == addr) {
                // update the string with the original name in the header
                // since we will be dumping that later we get a nicer binary to disassemble
                // C4 tool also depends on having the original symbol names
                // ☠️ YOLO ALL THE WAY ☠️
                strcpy(sym, oursymtable[x].name);
                break;
            }
        }
        DEBUG_MSG("%02d - Obfuscated symbol @ 0x%06" PRIx64 " is \"%s\"", i, addr, sym);
    }

    // fix some section names because YES WE CAN! 👍
    // XXX: to merge or not with the initial parsing, that's the question!
    lc = (struct load_command*)(buf + sizeof(struct mach_header_64));
    int cstring_idx = 0;
    for (size_t i = 0; i < mh->ncmds; i++) {
        switch (lc->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *sg = (struct segment_command_64*)lc;                
                // name is mangled so try to use the EXECUTE protection to distinguish the segment
                if ((sg->maxprot & VM_PROT_EXECUTE) && (sg->initprot & VM_PROT_EXECUTE)) {
                    struct section_64 *sc = (struct section_64*)((char*)sg + sizeof(struct segment_command_64));
                    for (size_t x = 0; x < sg->nsects; x++) {
                        snprintf(sc->segname, sizeof(sc->segname), "__TEXT");
                        switch (sc->flags & SECTION_TYPE) {
                        case S_SYMBOL_STUBS:
                            snprintf(sc->sectname, sizeof(sc->sectname), "__stubs");
                            break;
                        case S_CSTRING_LITERALS:
                            // potentially more than one so use an index
                            snprintf(sc->sectname, sizeof(sc->sectname), "__cstring%d", cstring_idx++);
                            break;
                        case S_REGULAR:
                            {
                                uint32_t attr = sc->flags & SECTION_ATTRIBUTES;
                                if (attr & S_ATTR_PURE_INSTRUCTIONS && 
                                    attr & S_ATTR_SOME_INSTRUCTIONS)
                                {
                                    // alignment might not hold true?
                                    if (sc->align == 2) {
                                        snprintf(sc->sectname, sizeof(sc->sectname), "__stub_helper");
                                    } else if (sc->align == 4) {
                                        snprintf(sc->sectname, sizeof(sc->sectname), "__text");
                                    }
                                }
                                break;
                            }
                        }
                        sc = (struct section_64*)((char*)sc + sizeof(struct section_64));
                    }
                }
                // __DATA
                int32_t prot = VM_PROT_READ | VM_PROT_WRITE;
                if (sg->maxprot == prot && sg->initprot == prot) {
                    struct section_64 *sc = (struct section_64*)((char*)sg + sizeof(struct segment_command_64));
                    for (size_t x = 0; x < sg->nsects; x++) {
                        snprintf(sc->segname, sizeof(sc->segname), "__DATA");
                        switch (sc->flags & SECTION_TYPE) {
                        case S_LAZY_SYMBOL_POINTERS:
                            snprintf(sc->sectname, sizeof(sc->sectname), "__la_symbol_ptr");
                            break;
                        case S_MOD_INIT_FUNC_POINTERS:
                            snprintf(sc->sectname, sizeof(sc->sectname), "__mod_init_func");
                            break;
                        }
                        sc = (struct section_64*)((char*)sc + sizeof(struct section_64));
                    }
                }
                break;
            }
            default: 
                break;            
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }

    return 0;
}
