/*
 *
 * 🧨 semtex - A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 * (c) fG!, 2025-2026 - reverser@put.as - https://reverse.put.as
 *
 */

#pragma once

#include <stdint.h>
#include <unicorn/unicorn.h>

struct user_data {
	uint64_t mprotect_stub;			// the address of _mprotect stub to hook
	uint64_t dyld_get_slide_stub;	// the same for __dyld_get_image_vmaddr_slide
	uint64_t load_method;			// the address of the entrypoint load method
};

void unicorn_hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
bool unicorn_hook_unmapped_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
bool unicorn_hook_write_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
