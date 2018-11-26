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
#include "crypto.h"

#if defined(INTEL_X64) || defined(__aarch64__)
#define HAS_AESNI_SUPPORT
#endif

namespace crypto {

class aesni_enc128_t
{
public:
  static bool supported();

  aesni_enc128_t() {}
  aesni_enc128_t(buf128_t key)  { init(key); }
  void init(buf128_t key);
  buf128_t encrypt(buf128_t in) const;

  void encrypt(buf128_t src1, buf128_t& dst1,
               buf128_t src2, buf128_t& dst2,
               buf128_t src3, buf128_t& dst3,
               buf128_t src4, buf128_t& dst4) const;

  void encrypt(buf128_t src1, buf128_t& dst1,
               buf128_t src2, buf128_t& dst2) const;

private:
#if defined(INTEL_X64)
  __m128i sched[11];
#elif defined(__aarch64__)
   uint8x16_t sched[11];
#endif
};

class aes_enc128_openssl_t
{
public:
  aes_enc128_openssl_t() : ctx(nullptr) {}
  ~aes_enc128_openssl_t();
  aes_enc128_openssl_t(buf128_t key)  { init(key); }

  void init(buf128_t key);
  buf128_t encrypt(buf128_t in) const;

  void encrypt(buf128_t src1, buf128_t& dst1,
               buf128_t src2, buf128_t& dst2,
               buf128_t src3, buf128_t& dst3,
               buf128_t src4, buf128_t& dst4) const;

  void encrypt(buf128_t src1, buf128_t& dst1,
               buf128_t src2, buf128_t& dst2) const;

private:
  EVP_CIPHER_CTX* ctx;
};

class aes_enc128_t
{
public:
#ifdef HAS_AESNI_SUPPORT
  aes_enc128_t(bool use_aesni=true);
  aes_enc128_t(buf128_t key, bool use_aesni=true);
#else
  aes_enc128_t(bool use_aesni=false);
  aes_enc128_t(buf128_t key, bool use_aesni=false);
#endif

  void init(buf128_t key);
  buf128_t encrypt(buf128_t in) const;

  void encrypt(buf128_t src1, buf128_t& dst1,
               buf128_t src2, buf128_t& dst2,
               buf128_t src3, buf128_t& dst3,
               buf128_t src4, buf128_t& dst4) const;

  void encrypt(buf128_t src1, buf128_t& dst1,
               buf128_t src2, buf128_t& dst2) const;

  aes_enc128_openssl_t& get_openssl() { return openssl; }
  aesni_enc128_t& get_aesni() { return aesni; }
  bool use_aesni() const { return mode_aesni; }

private:
  bool mode_aesni;
  aes_enc128_openssl_t openssl;
  aesni_enc128_t aesni;
};



} // namespace crypto