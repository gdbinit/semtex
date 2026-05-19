/*
 *
 * 🧨 semtex - A Unicorn Emulator to dump obfuscated code from TNT team x86_64 crack library
 * (c) fG!, 2025-2026 - reverser@put.as - https://reverse.put.as
 *
 */

#include <stdio.h>
#include <inttypes.h>
#include "Zydis.h"

void print_disasm(unsigned char *buf, size_t buf_size) 
{
    ZydisDecoder decoder = {0};
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZyanStatus status;
    ZydisDecodedInstruction inst;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    char format_buffer[256];

    uint8_t *readPointer = buf;
    size_t length = buf_size;
    uint64_t ip = 0;
    while ((status = ZydisDecoderDecodeFull(&decoder, readPointer, length, &inst, ops)) != ZYDIS_STATUS_NO_MORE_DATA) {
        // this is one hell of a long 🚂 call...
        ZydisFormatterFormatInstruction(&formatter, &inst, ops, inst.operand_count_visible, format_buffer, sizeof(format_buffer), ip, ZYAN_NULL);
        printf("0x%" PRIx64 " %s\n", ip, format_buffer);
        readPointer += inst.length;
        length -= inst.length;
        ip += inst.length;
    }
}
