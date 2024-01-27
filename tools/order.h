/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_TOOL_ORDER_H_
#define _KP_TOOL_ORDER_H_

#include <stdint.h>

#define is_be() (*(unsigned char *)&(uint16_t){ 1 } ? 0 : 1)

int16_t i16swp(int16_t val);
int16_t i16le(int16_t val);
int16_t i16be(int16_t val);

uint16_t u16swp(uint16_t val);
uint16_t u16le(uint16_t val);
uint16_t u16be(uint16_t val);

int32_t i32swp(int32_t val);
int32_t i32le(int32_t val);
int32_t i32be(int32_t val);

uint32_t u32swp(uint32_t val);
uint32_t u32le(uint32_t val);
uint32_t u32be(uint32_t val);

int64_t i64swp(int64_t val);
int64_t i64le(int64_t val);
int64_t i64be(int64_t val);

uint64_t u64swp(uint64_t val);
uint64_t u64le(uint64_t val);
uint64_t u64be(uint64_t val);

#endif // _ORDER_H_