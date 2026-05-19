/*
 *
 * 🧨 semtex - A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 * (c) fG!, 2025-2026 - reverser@put.as - https://reverse.put.as
 *
 */

#pragma once

// the addresses where we will install the code and stack space - since it's PIE code we can run it anywhere we want
#define CODE_ADDRESS    0x0
#define CODE_SIZE       20 * 1024 * 1024
#define STACK_ADDRESS   0xBFF00000
#define STACK_SIZE      10 * 1024 * 1024
