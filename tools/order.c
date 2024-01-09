/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "order.h"

inline uint16_t u16swp(uint16_t val)
{
    return (val << 8) | (val >> 8);
}

inline int16_t i16swp(int16_t val)
{
    return (val << 8) | ((val >> 8) & 0xFF);
}

uint16_t u16le(uint16_t val)
{
    return is_be() ? u16swp(val) : val;
}

uint16_t u16be(uint16_t val)
{
    return is_be() ? val : u16swp(val);
}

int16_t i16le(int16_t val)
{
    return is_be() ? i16swp(val) : val;
}

int16_t i16be(int16_t val)
{
    return is_be() ? val : i16swp(val);
}

uint32_t u32swp(uint32_t val)
{
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | (val >> 16);
}

int32_t i32swp(int32_t val)
{
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | ((val >> 16) & 0xFFFF);
}

uint32_t u32le(uint32_t val)
{
    return is_be() ? u32swp(val) : val;
}

uint32_t u32be(uint32_t val)
{
    return is_be() ? val : u32swp(val);
}

int32_t i32le(int32_t val)
{
    return is_be() ? i32swp(val) : val;
}

int32_t i32be(int32_t val)
{
    return is_be() ? val : i32swp(val);
}

int64_t i64swp(int64_t val)
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | ((val >> 32) & 0xFFFFFFFFULL);
}

uint64_t u64swp(uint64_t val)
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}

int64_t i64le(int64_t val)
{
    return is_be() ? i64swp(val) : val;
}

int64_t i64be(int64_t val)
{
    return is_be() ? val : i64swp(val);
}

uint64_t u64le(uint64_t val)
{
    return is_be() ? u64swp(val) : val;
}

uint64_t u64be(uint64_t val)
{
    return is_be() ? val : u64swp(val);
}
