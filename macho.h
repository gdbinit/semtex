/*
 *
 * 🧨 semtex - A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 * (c) fG!, 2025-2026 - reverser@put.as - https://reverse.put.as
 *
 */

#pragma once

#include <stdio.h>
#include <stdint.h>

#include "hooks.h"

int parse_macho(unsigned char *buf, size_t buf_size, struct user_data *udata);

#ifdef __APPLE__
#	include <mach-o/loader.h>
#	include <mach-o/nlist.h>

#elif __linux

//
// types ripped from Apple headers
// only the minimum necessary taken
//

/* Constant for the magic field of the mach_header (32-bit architectures) */
#define MH_MAGIC        0xfeedface      /* the mach magic number */
#define MH_CIGAM        0xcefaedfe      /* NXSwapInt(MH_MAGIC) */

struct mach_header_64 {
        uint32_t        magic;          /* mach magic number identifier */
        int32_t         cputype;        /* cpu specifier */
        int32_t         cpusubtype;     /* machine specifier */
        uint32_t        filetype;       /* type of file */
        uint32_t        ncmds;          /* number of load commands */
        uint32_t        sizeofcmds;     /* the size of all the load commands */
        uint32_t        flags;          /* flags */
        uint32_t        reserved;       /* reserved */
};

/* Constant for the magic field of the mach_header_64 (64-bit architectures) */
#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */


struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};

#define LC_REQ_DYLD 0x80000000

/* Constants for the cmd field of all load commands, the type */
#define LC_SYMTAB       0x2     /* link-edit stab symbol table info */
#define LC_DYSYMTAB     0xb     /* dynamic link-edit symbol table info */

#define LC_SEGMENT_64   0x19    /* 64-bit segment of this file to be
                                   mapped */
#define LC_DYLD_INFO    0x22    /* compressed dyld information */
#define LC_DYLD_INFO_ONLY (0x22|LC_REQ_DYLD)    /* compressed dyld information only */

union lc_str {
        uint32_t        offset; /* offset to the string */
#ifndef __LP64__
        char            *ptr;   /* pointer to the string */
#endif
};

struct segment_command_64 { /* for 64-bit architectures */
        uint32_t        cmd;            /* LC_SEGMENT_64 */
        uint32_t        cmdsize;        /* includes sizeof section_64 structs */
        char            segname[16];    /* segment name */
        uint64_t        vmaddr;         /* memory address of this segment */
        uint64_t        vmsize;         /* memory size of this segment */
        uint64_t        fileoff;        /* file offset of this segment */
        uint64_t        filesize;       /* amount to map from the file */
        int32_t         maxprot;        /* maximum VM protection */
        int32_t         initprot;       /* initial VM protection */
        uint32_t        nsects;         /* number of sections in segment */
        uint32_t        flags;          /* flags */
};

struct section_64 { /* for 64-bit architectures */
        char            sectname[16];   /* name of this section */
        char            segname[16];    /* segment this section goes in */
        uint64_t        addr;           /* memory address of this section */
        uint64_t        size;           /* size in bytes of this section */
        uint32_t        offset;         /* file offset of this section */
        uint32_t        align;          /* section alignment (power of 2) */
        uint32_t        reloff;         /* file offset of relocation entries */
        uint32_t        nreloc;         /* number of relocation entries */
        uint32_t        flags;          /* flags (section type and attributes)*/
        uint32_t        reserved1;      /* reserved (for offset or index) */
        uint32_t        reserved2;      /* reserved (for count or sizeof) */
        uint32_t        reserved3;      /* reserved */
};

#define SECTION_TYPE             0x000000ff     /* 256 section types */
#define SECTION_ATTRIBUTES       0xffffff00     /*  24 section attributes */

#define S_REGULAR               0x0     /* regular section */
#define S_ZEROFILL              0x1     /* zero fill on demand section */
#define S_CSTRING_LITERALS      0x2     /* section with only literal C strings*/
#define S_4BYTE_LITERALS        0x3     /* section with only 4 byte literals */
#define S_8BYTE_LITERALS        0x4     /* section with only 8 byte literals */
#define S_LITERAL_POINTERS      0x5     /* section with only pointers to */
                                        /*  literals */
#define S_NON_LAZY_SYMBOL_POINTERS      0x6     /* section with only non-lazy
                                                   symbol pointers */
#define S_LAZY_SYMBOL_POINTERS          0x7     /* section with only lazy symbol
                                                   pointers */
#define S_SYMBOL_STUBS                  0x8     /* section with only symbol
                                                   stubs, byte size of stub in
                                                   the reserved2 field */
#define S_MOD_INIT_FUNC_POINTERS        0x9     /* section with only function
                                                   pointers for initialization*/
#define S_MOD_TERM_FUNC_POINTERS        0xa     /* section with only function
                                                   pointers for termination */
#define S_ATTR_PURE_INSTRUCTIONS 0x80000000     /* section contains only true
                                                   machine instructions */
#define S_ATTR_SOME_INSTRUCTIONS 0x00000400     /* section contains some
                                                   machine instructions */

struct dylib {
    union lc_str  name;                 /* library's path name */
    uint32_t timestamp;                 /* library's build time stamp */
    uint32_t current_version;           /* library's current version number */
    uint32_t compatibility_version;     /* library's compatibility vers number*/
};

struct dylib_command {
        uint32_t        cmd;            /* LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB,
                                           LC_REEXPORT_DYLIB */
        uint32_t        cmdsize;        /* includes pathname string */
        struct dylib    dylib;          /* the library identification */
};

#define INDIRECT_SYMBOL_LOCAL   0x80000000 
#define INDIRECT_SYMBOL_ABS     0x40000000 

struct symtab_command {
        uint32_t        cmd;            /* LC_SYMTAB */
        uint32_t        cmdsize;        /* sizeof(struct symtab_command) */
        uint32_t        symoff;         /* symbol table offset */
        uint32_t        nsyms;          /* number of symbol table entries */
        uint32_t        stroff;         /* string table offset */
        uint32_t        strsize;        /* string table size in bytes */
};  

struct dysymtab_command {
    uint32_t cmd;       /* LC_DYSYMTAB */
    uint32_t cmdsize;   /* sizeof(struct dysymtab_command) */
    uint32_t ilocalsym; /* index to local symbols */
    uint32_t nlocalsym; /* number of local symbols */
    uint32_t iextdefsym;/* index to externally defined symbols */
    uint32_t nextdefsym;/* number of externally defined symbols */ 
    uint32_t iundefsym; /* index to undefined symbols */
    uint32_t nundefsym; /* number of undefined symbols */
    uint32_t tocoff;    /* file offset to table of contents */
    uint32_t ntoc;      /* number of entries in table of contents */
    uint32_t modtaboff; /* file offset to module table */
    uint32_t nmodtab;   /* number of module table entries */
    uint32_t extrefsymoff;      /* offset to referenced symbol table */
    uint32_t nextrefsyms;       /* number of referenced symbol table entries */
    uint32_t indirectsymoff; /* file offset to the indirect symbol table */
    uint32_t nindirectsyms;  /* number of indirect symbol table entries */
    uint32_t extreloff; /* offset to external relocation entries */
    uint32_t nextrel;   /* number of external relocation entries */
    uint32_t locreloff; /* offset to local relocation entries */
    uint32_t nlocrel;   /* number of local relocation entries */
};     
 
#define BIND_OPCODE_MASK                                        0xF0
#define BIND_IMMEDIATE_MASK                                     0x0F
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM               0x40
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB                 0x70
#define BIND_OPCODE_DO_BIND                                     0x90

struct dyld_info_command {
    uint32_t   cmd;              /* LC_DYLD_INFO or LC_DYLD_INFO_ONLY */
    uint32_t   cmdsize;          /* sizeof(struct dyld_info_command) */
    uint32_t   rebase_off;      /* file offset to rebase info  */
    uint32_t   rebase_size;     /* size of rebase info   */     
    uint32_t   bind_off;        /* file offset to binding info   */
    uint32_t   bind_size;       /* size of binding info  */
    uint32_t   weak_bind_off;   /* file offset to weak binding info   */
    uint32_t   weak_bind_size;  /* size of weak binding info  */
    uint32_t   lazy_bind_off;   /* file offset to lazy binding info */
    uint32_t   lazy_bind_size;  /* size of lazy binding infs */
    uint32_t   export_off;      /* file offset to lazy binding info */
    uint32_t   export_size;     /* size of lazy binding infs */
};

typedef int             vm_prot_t;

#define VM_PROT_NONE    ((vm_prot_t) 0x00) 
 
#define VM_PROT_READ    ((vm_prot_t) 0x01)      /* read permission */
#define VM_PROT_WRITE   ((vm_prot_t) 0x02)      /* write permission */
#define VM_PROT_EXECUTE ((vm_prot_t) 0x04)      /* execute permission */

typedef int             integer_t;
typedef integer_t       cpu_type_t;
typedef integer_t       cpu_subtype_t;
typedef integer_t       cpu_threadtype_t;

#define CPU_ARCH_MASK           0xff000000      /* mask for architecture bits */
#define CPU_ARCH_ABI64          0x01000000      /* 64 bit ABI */ 
 
#define CPU_TYPE_ANY            ((cpu_type_t) -1) 
#define CPU_TYPE_X86            ((cpu_type_t) 7)
#define CPU_TYPE_X86_64         (CPU_TYPE_X86 | CPU_ARCH_ABI64)

struct nlist_64 {
    union {
        uint32_t  n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;        /* type flag, see below */
    uint8_t n_sect;        /* section number or NO_SECT */
    uint16_t n_desc;       /* see <mach-o/stab.h> */
    uint64_t n_value;      /* value of this symbol (or stab offset) */
};

#endif
