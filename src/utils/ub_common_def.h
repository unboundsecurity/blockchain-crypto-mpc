/*
 *     NOTICE
 *
 *     The blockchain-crypto-mpc software is licensed under a proprietary license or the GPL v.3. 
 *     If you choose to receive it under the GPL v.3 license, the following applies:
 *     Blockchain-crypto-mpc is a Multiparty Computation (MPC)-based cryptographic library for securing blockchain wallets and applications.
 *     
 *     Copyright (C) 2018, Unbound Tech Ltd. 
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 * 
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 * 
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <assert.h>

#include <string>
#include <algorithm>
#include <queue>
#include <vector>
#include <list>
#include <map>
#include <memory>

#ifdef __aarch64__
#include <arm_neon.h>
#endif

#ifdef __APPLE__
#include "TargetConditionals.h"

#if TARGET_OS_IOS || TARGET_OS_TV || TARGET_OS_WATCH
#define TARGET_OS_IOSX 1
#endif

#endif

#if defined(_WIN32) || defined(__APPLE__) || defined(__ANDROID__)
#include <unordered_map>
#include <unordered_set>
#else
#include <tr1/unordered_map>
#include <tr1/unordered_set>
#endif

#if !defined(_WIN64) && defined(_WIN32)
#define WINDOWS_32BIT
#endif

#if defined(_WIN64) || defined(__x86_64__)
#define INTEL_X64
#endif

#if (!defined(__LITTLE_ENDIAN__) && \
       (   defined(INTEL_X64) \
        || defined(_WIN32) \
        || defined(_M_IX86) \
        || defined(__i386__) \
        || (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))))
#define __LITTLE_ENDIAN__
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef max
#undef max
#endif

#ifdef max
#undef min
#endif

#else
#ifdef INTEL_X64
extern "C"
{
#include <x86intrin.h>
//#include <wmmintrin.h>
}
#endif

#include <semaphore.h>
#include <pthread.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#endif

#ifdef _WIN32
#define STDCALL __stdcall
#define SELECTANY __declspec(selectany)
#define DLLEXPORT __declspec(dllexport)
#define DLLEXPORT_DEF
#else
#define STDCALL
#define SELECTANY __attribute__  ((weak))
#define DLLEXPORT __attribute__  ((visibility("default")))
#define DLLEXPORT_DEF DLLEXPORT
#endif


#ifndef NULL
#define NULL ((void*)0)
#endif

#ifdef __GNUC__
#define GCC_VERSION ((__GNUC__ << 8) | __GNUC_MINOR__)
#endif

#if defined(__GNUC__) && (GCC_VERSION < 0x0406) // 4.6
#define nullptr NULL
#endif
#if defined(__GNUC__) && (GCC_VERSION < 0x0407) // 4.7
#define override
#endif

#define FOR_EACH(i, c) for (auto i=(c).begin(); i!=(c).end(); ++i)

typedef void* void_ptr;
typedef const void* const_void_ptr;

typedef uint8_t byte_t;
typedef byte_t* byte_ptr;
typedef const byte_t* const_byte_ptr;

typedef char* char_ptr;
typedef const char* const_char_ptr;

struct null_data_t;
typedef null_data_t* null_ptr_t;

#if defined(_WIN32) || defined(__APPLE__) || defined(__ANDROID__)
#define unordered_map_t std::unordered_map
#define unordered_set_t std::unordered_set
#else
#define unordered_map_t std::tr1::unordered_map
#define unordered_set_t std::tr1::unordered_set
#endif

#ifndef _countof
#define _countof(x) (sizeof(x)/sizeof((x)[0]))
#endif
