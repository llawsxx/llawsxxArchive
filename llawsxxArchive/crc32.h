#pragma once
#include <stdint.h>
typedef struct {
	uint32_t crc;
} CRC32_Context;
void crc32_init(CRC32_Context* ctx);
void crc32_update(CRC32_Context* ctx, const void* data, size_t len);
uint32_t crc32_final(CRC32_Context* ctx);
uint32_t crc32_calc(const void* data, size_t len);
