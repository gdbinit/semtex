/*
 *
 * 🧨 semtex - A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 * (c) fG!, 2025 - reverser@put.as - https://reverse.put.as
 *
 */

#pragma once

#include <stdio.h>
#include "hooks.h"

int parse_macho(unsigned char *buf, size_t buf_size, struct user_data *udata);
