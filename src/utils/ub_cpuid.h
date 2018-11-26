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

#include "ub_common.h"

namespace ub {

namespace cpuid {

bool is_little_endian();
bool is_big_endian();

#if defined(__aarch64__)
bool has_neon();
bool has_arm_sha1();
bool has_arm_sha2();
bool has_arm_aes();
#define has_aes_ni has_arm_aes
#elif defined(INTEL_X64)

bool has_rdtsc();
bool has_sse2();
bool has_avx2();
bool has_bmi2();
bool has_aes_ni();
bool has_intel_sha();
bool has_rdrand();
bool has_rdseed();

#else
bool has_aes_ni();
#endif

} //namespace cpuid

} // namespace ub

