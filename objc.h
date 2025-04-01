/*
 *
 * 🧨 semtex - A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 * (c) fG!, 2025 - reverser@put.as - https://reverse.put.as
 *
 * Ripped from IDA and Objective-C runtime
 *
 */

#pragma once

#include <stdint.h>

typedef void *id;
typedef const char *SEL;
typedef id (*IMP)(id, SEL, ...);

struct __objc2_meth_list
{
    uint32_t entrysize;
    uint32_t count;
};

struct __objc2_meth
{
    char *name;
    char *types;
    IMP imp;
};

struct __objc2_prot_list
{
    uint64_t count;
};

struct __objc2_ivar_list
{
    uint32_t entrysize;
    uint32_t count;
};

struct __objc2_prop_list
{
    uint32_t entrysize;
    uint32_t count;
};

struct __objc2_class_ro
{
    uint32_t flags;
    uint32_t ivar_base_start;
    uint32_t ivar_base_size;
    uint32_t reserved;
    void *ivar_lyt;
    char *name;
    struct __objc2_meth_list *base_meths;
    struct __objc2_prot_list *base_prots;
    struct __objc2_ivar_list *ivars;
    void *weak_ivar_lyt;
    struct __objc2_prop_list *base_props;
};

struct __objc2_class
{
    struct __objc2_class *isa;
    struct __objc2_class *superclass;
    void *cache;
    void *vtable;
    struct __objc2_class_ro *info;
};
