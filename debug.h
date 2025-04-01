/*
 *
 * 🧨 semtex - A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 * (c) fG!, 2025 - reverser@put.as - https://reverse.put.as
 *
 */

#pragma once

#include <unicorn/unicorn.h>

void print_x64_registers(uc_engine *uc);
void print_stack(uc_engine *uc);
