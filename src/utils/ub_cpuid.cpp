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

#include "precompiled.h"
#include "ub_cpuid.h"

#if defined(__aarch64__) && !defined(__APPLE__)
#include <sys/auxv.h> 
#endif

namespace ub {

namespace cpuid {

#if defined(__aarch64__)
static bool NEON=false;
static bool ARM_SHA1=false;
static bool ARM_SHA2=false;
static bool ARM_AES=false;

static void init()
{
  static bool initialized = false;
  if (initialized) return;

#if defined(__APPLE__)
  NEON=true;
  ARM_SHA1=true;
  ARM_SHA2=true;
  ARM_AES=true;
#else
  unsigned hwcap = getauxval(AT_HWCAP);
  NEON = ((hwcap>>1) & 1) ? true : false;

  ARM_AES  = ((hwcap>>3) & 1) ? true : false;
  ARM_SHA1 = ((hwcap>>5) & 1) ? true : false;
  ARM_SHA2 = ((hwcap>>6) & 1) ? true : false;
#endif

  initialized = true;
}


bool has_neon()          { init(); return NEON; }
bool has_arm_sha1()      { init(); return ARM_SHA1; }
bool has_arm_sha2()      { init(); return ARM_SHA2; }
bool has_arm_aes()       { init(); return ARM_AES; }

#elif defined(INTEL_X64)

static bool SSE2=false;
static bool AVX2=false;

static bool RDTSC=false;
static bool BMI2=false;

static bool AESNI=false;
static bool RDRAND=false;
static bool RDSEED=false;
static bool SHA=false;

static void get_cpuid(int type, int* out)
{
#if defined(_WIN32)
  __cpuid(out, type);
#else
  asm("cpuid\n\t" : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3]) : "0" (type));
#endif
}

static void get_cpuid_sublevel(int type, int level, int* out)
{
#if defined(_WIN32)
  __cpuidex(out, type, level);
#else
   asm("cpuid\n\t" : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3]) : "0" (type), "2" (level));
#endif
}


static void init()
{
  static bool initialized = false;
  if (initialized) return;

  int data[4] = {0};
  get_cpuid(0, data);
  int max_level = data[0];
  //bool intel = data[1]=='Genu' && data[2]=='ntel' && data[3]=='ineI';
  //bool amd   = data[1]=='Auth' && data[2]=='cAMD' && data[3]=='enti';

  if (max_level >= 1)
  {
    data[2]=data[3]=0; get_cpuid(1, data);
    RDTSC  = ((data[3] >>  4) & 1) ? true : false;
    SSE2   = ((data[3] >> 26) & 1) ? true : false;
    AESNI  = ((data[2] >> 25) & 1) ? true : false;
    RDRAND = ((data[2] >> 30) & 1) ? true : false;

    if (max_level >= 7)
    {
      data[1]=0; get_cpuid_sublevel(7, 0, data);
      AVX2   = ((data[1] >>  5) & 1) ? true : false;
      BMI2   = ((data[1] >>  8) & 1) ? true : false;
      RDSEED = ((data[1] >> 18) & 1) ? true : false;
      SHA    = ((data[1] >> 29) & 1) ? true : false;
    }
  }

  initialized = true;
}

bool has_rdtsc()      { init(); return RDTSC;  }
bool has_sse2()       { init(); return SSE2;   }
bool has_avx2()       { init(); return AVX2;   }
bool has_bmi2()       { init(); return BMI2;   }
bool has_aes_ni()     { init(); return AESNI;  }
bool has_intel_sha()  { init(); return SHA;    }
bool has_rdrand()     { init(); return RDRAND; }
bool has_rdseed()     { init(); return RDSEED; }

#else
bool has_aes_ni()     { return false;  }
#endif


bool is_little_endian()
{
#if defined(_WIN32) || defined(__i386__) || defined(__x86_64__)
  return true;
#else
  const uint16_t test = 1;
  return *(uint8_t*)&test == 1;
#endif
}

bool is_big_endian() { return !is_little_endian(); }

} //namespace cpuid

} // namespace ub
