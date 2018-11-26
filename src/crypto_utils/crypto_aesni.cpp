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
#include "crypto_aesni.h"
#include "ub_cpuid.h"

namespace crypto {

#if defined(INTEL_X64)

#if !defined(_WIN32) && !defined(_mm_aeskeygenassist_si128)
#define _mm_aeskeygenassist_si128(x, rc) \
({ \
  __m128i out; \
  asm("aeskeygenassist %2, %1, %0" : "=x"(out) : "x"(x), "g"(rc)); \
  out; \
})

inline __m128i _mm_aesenc_si128(__m128i in, __m128i sched)
{
  __m128i out = in;
  asm("aesenc %1, %0" : "+x"(out) : "x"(sched));
  return out;
}

inline __m128i _mm_aesenclast_si128(__m128i in, __m128i sched)
{
  __m128i out = in;
  asm("aesenclast %1, %0" : "+x"(out) : "x"(sched));
  return out;
}
#endif

#define AES_EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                \
    v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2)


void aesni_enc128_t::init(buf128_t key)
{
  __m128i x0,x1,x2;
  sched[0] = x0 = key.value;
  x2 = _mm_setzero_si128();
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 1);   sched[1]  = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 2);   sched[2]  = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 4);   sched[3]  = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 8);   sched[4]  = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 16);  sched[5]  = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 32);  sched[6]  = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 64);  sched[7]  = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 128); sched[8]  = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 27);  sched[9]  = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 54);  sched[10] = x0;
}

buf128_t aesni_enc128_t::encrypt(buf128_t in) const
{
  __m128i encrypted = _mm_xor_si128(in.value, sched[0]);
  encrypted = _mm_aesenc_si128(encrypted, sched[1]);
  encrypted = _mm_aesenc_si128(encrypted, sched[2]);
  encrypted = _mm_aesenc_si128(encrypted, sched[3]);
  encrypted = _mm_aesenc_si128(encrypted, sched[4]);
  encrypted = _mm_aesenc_si128(encrypted, sched[5]);
  encrypted = _mm_aesenc_si128(encrypted, sched[6]);
  encrypted = _mm_aesenc_si128(encrypted, sched[7]);
  encrypted = _mm_aesenc_si128(encrypted, sched[8]);
  encrypted = _mm_aesenc_si128(encrypted, sched[9]);
  encrypted = _mm_aesenclast_si128(encrypted, sched[10]);
  buf128_t e;
  e.value = encrypted;
  return e;
}

static void aesni_encrypt_round(buf128_t& x1, buf128_t& x2, buf128_t& x3, buf128_t& x4, __m128i sched)
{
  x1.value = _mm_aesenc_si128(x1.value, sched);
  x2.value = _mm_aesenc_si128(x2.value, sched);
  x3.value = _mm_aesenc_si128(x3.value, sched);
  x4.value = _mm_aesenc_si128(x4.value, sched);
}

static void aesni_encrypt_round(buf128_t& x1, buf128_t& x2, __m128i sched)
{
  x1.value = _mm_aesenc_si128(x1.value, sched);
  x2.value = _mm_aesenc_si128(x2.value, sched);
}


void aesni_enc128_t::encrypt(buf128_t src1, buf128_t& dst1,
                             buf128_t src2, buf128_t& dst2,
                             buf128_t src3, buf128_t& dst3,
                             buf128_t src4, buf128_t& dst4) const
{
  src1.value = _mm_xor_si128(src1.value, sched[0]);
  src2.value = _mm_xor_si128(src2.value, sched[0]);
  src3.value = _mm_xor_si128(src3.value, sched[0]);
  src4.value = _mm_xor_si128(src4.value, sched[0]);

  aesni_encrypt_round(src1, src2, src3, src4, sched[1]);
  aesni_encrypt_round(src1, src2, src3, src4, sched[2]);
  aesni_encrypt_round(src1, src2, src3, src4, sched[3]);
  aesni_encrypt_round(src1, src2, src3, src4, sched[4]);
  aesni_encrypt_round(src1, src2, src3, src4, sched[5]);
  aesni_encrypt_round(src1, src2, src3, src4, sched[6]);
  aesni_encrypt_round(src1, src2, src3, src4, sched[7]);
  aesni_encrypt_round(src1, src2, src3, src4, sched[8]);
  aesni_encrypt_round(src1, src2, src3, src4, sched[9]);

  dst1.value = _mm_aesenclast_si128(src1.value, sched[10]);
  dst2.value = _mm_aesenclast_si128(src2.value, sched[10]);
  dst3.value = _mm_aesenclast_si128(src3.value, sched[10]);
  dst4.value = _mm_aesenclast_si128(src4.value, sched[10]);
}


void aesni_enc128_t::encrypt(buf128_t src1, buf128_t& dst1,
                             buf128_t src2, buf128_t& dst2) const
{
  src1.value = _mm_xor_si128(src1.value, sched[0]);
  src2.value = _mm_xor_si128(src2.value, sched[0]);

  aesni_encrypt_round(src1, src2, sched[1]);
  aesni_encrypt_round(src1, src2, sched[2]);
  aesni_encrypt_round(src1, src2, sched[3]);
  aesni_encrypt_round(src1, src2, sched[4]);
  aesni_encrypt_round(src1, src2, sched[5]);
  aesni_encrypt_round(src1, src2, sched[6]);
  aesni_encrypt_round(src1, src2, sched[7]);
  aesni_encrypt_round(src1, src2, sched[8]);
  aesni_encrypt_round(src1, src2, sched[9]);

  dst1.value = _mm_aesenclast_si128(src1.value, sched[10]);
  dst2.value = _mm_aesenclast_si128(src2.value, sched[10]);
}

bool aesni_enc128_t::supported() 
{
  return ub::cpuid::has_aes_ni();
}

#elif defined(__aarch64__)

static void rijndael128KeySetupEnc(uint32_t rk[/*4*(Nr + 1)*/], const uint8_t cipherKey[])
{
  static const uint64_t rcon[] =
  {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000, /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
  };

  static const uint32_t Te4[256] =
  {
    0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7b7b7bU, 0xf2f2f2f2U, 0x6b6b6b6bU, 0x6f6f6f6fU, 0xc5c5c5c5U, 0x30303030U, 0x01010101U, 0x67676767U, 0x2b2b2b2bU, 0xfefefefeU, 0xd7d7d7d7U, 0xababababU, 0x76767676U,
    0xcacacacaU, 0x82828282U, 0xc9c9c9c9U, 0x7d7d7d7dU, 0xfafafafaU, 0x59595959U, 0x47474747U, 0xf0f0f0f0U, 0xadadadadU, 0xd4d4d4d4U, 0xa2a2a2a2U, 0xafafafafU, 0x9c9c9c9cU, 0xa4a4a4a4U, 0x72727272U, 0xc0c0c0c0U,
    0xb7b7b7b7U, 0xfdfdfdfdU, 0x93939393U, 0x26262626U, 0x36363636U, 0x3f3f3f3fU, 0xf7f7f7f7U, 0xccccccccU, 0x34343434U, 0xa5a5a5a5U, 0xe5e5e5e5U, 0xf1f1f1f1U, 0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x15151515U,
    0x04040404U, 0xc7c7c7c7U, 0x23232323U, 0xc3c3c3c3U, 0x18181818U, 0x96969696U, 0x05050505U, 0x9a9a9a9aU, 0x07070707U, 0x12121212U, 0x80808080U, 0xe2e2e2e2U, 0xebebebebU, 0x27272727U, 0xb2b2b2b2U, 0x75757575U,
    0x09090909U, 0x83838383U, 0x2c2c2c2cU, 0x1a1a1a1aU, 0x1b1b1b1bU, 0x6e6e6e6eU, 0x5a5a5a5aU, 0xa0a0a0a0U, 0x52525252U, 0x3b3b3b3bU, 0xd6d6d6d6U, 0xb3b3b3b3U, 0x29292929U, 0xe3e3e3e3U, 0x2f2f2f2fU, 0x84848484U,
    0x53535353U, 0xd1d1d1d1U, 0x00000000U, 0xededededU, 0x20202020U, 0xfcfcfcfcU, 0xb1b1b1b1U, 0x5b5b5b5bU, 0x6a6a6a6aU, 0xcbcbcbcbU, 0xbebebebeU, 0x39393939U, 0x4a4a4a4aU, 0x4c4c4c4cU, 0x58585858U, 0xcfcfcfcfU,
    0xd0d0d0d0U, 0xefefefefU, 0xaaaaaaaaU, 0xfbfbfbfbU, 0x43434343U, 0x4d4d4d4dU, 0x33333333U, 0x85858585U, 0x45454545U, 0xf9f9f9f9U, 0x02020202U, 0x7f7f7f7fU, 0x50505050U, 0x3c3c3c3cU, 0x9f9f9f9fU, 0xa8a8a8a8U,
    0x51515151U, 0xa3a3a3a3U, 0x40404040U, 0x8f8f8f8fU, 0x92929292U, 0x9d9d9d9dU, 0x38383838U, 0xf5f5f5f5U, 0xbcbcbcbcU, 0xb6b6b6b6U, 0xdadadadaU, 0x21212121U, 0x10101010U, 0xffffffffU, 0xf3f3f3f3U, 0xd2d2d2d2U,
    0xcdcdcdcdU, 0x0c0c0c0cU, 0x13131313U, 0xececececU, 0x5f5f5f5fU, 0x97979797U, 0x44444444U, 0x17171717U, 0xc4c4c4c4U, 0xa7a7a7a7U, 0x7e7e7e7eU, 0x3d3d3d3dU, 0x64646464U, 0x5d5d5d5dU, 0x19191919U, 0x73737373U,
    0x60606060U, 0x81818181U, 0x4f4f4f4fU, 0xdcdcdcdcU, 0x22222222U, 0x2a2a2a2aU, 0x90909090U, 0x88888888U, 0x46464646U, 0xeeeeeeeeU, 0xb8b8b8b8U, 0x14141414U, 0xdedededeU, 0x5e5e5e5eU, 0x0b0b0b0bU, 0xdbdbdbdbU,
    0xe0e0e0e0U, 0x32323232U, 0x3a3a3a3aU, 0x0a0a0a0aU, 0x49494949U, 0x06060606U, 0x24242424U, 0x5c5c5c5cU, 0xc2c2c2c2U, 0xd3d3d3d3U, 0xacacacacU, 0x62626262U, 0x91919191U, 0x95959595U, 0xe4e4e4e4U, 0x79797979U,
    0xe7e7e7e7U, 0xc8c8c8c8U, 0x37373737U, 0x6d6d6d6dU, 0x8d8d8d8dU, 0xd5d5d5d5U, 0x4e4e4e4eU, 0xa9a9a9a9U, 0x6c6c6c6cU, 0x56565656U, 0xf4f4f4f4U, 0xeaeaeaeaU, 0x65656565U, 0x7a7a7a7aU, 0xaeaeaeaeU, 0x08080808U,
    0xbabababaU, 0x78787878U, 0x25252525U, 0x2e2e2e2eU, 0x1c1c1c1cU, 0xa6a6a6a6U, 0xb4b4b4b4U, 0xc6c6c6c6U, 0xe8e8e8e8U, 0xddddddddU, 0x74747474U, 0x1f1f1f1fU, 0x4b4b4b4bU, 0xbdbdbdbdU, 0x8b8b8b8bU, 0x8a8a8a8aU,
    0x70707070U, 0x3e3e3e3eU, 0xb5b5b5b5U, 0x66666666U, 0x48484848U, 0x03030303U, 0xf6f6f6f6U, 0x0e0e0e0eU, 0x61616161U, 0x35353535U, 0x57575757U, 0xb9b9b9b9U, 0x86868686U, 0xc1c1c1c1U, 0x1d1d1d1dU, 0x9e9e9e9eU,
    0xe1e1e1e1U, 0xf8f8f8f8U, 0x98989898U, 0x11111111U, 0x69696969U, 0xd9d9d9d9U, 0x8e8e8e8eU, 0x94949494U, 0x9b9b9b9bU, 0x1e1e1e1eU, 0x87878787U, 0xe9e9e9e9U, 0xcecececeU, 0x55555555U, 0x28282828U, 0xdfdfdfdfU,
    0x8c8c8c8cU, 0xa1a1a1a1U, 0x89898989U, 0x0d0d0d0dU, 0xbfbfbfbfU, 0xe6e6e6e6U, 0x42424242U, 0x68686868U, 0x41414141U, 0x99999999U, 0x2d2d2d2dU, 0x0f0f0f0fU, 0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U,
  };

  int i = 0;
  uint32_t temp;

  rk[0] = ub::be_get_4(cipherKey);
  rk[1] = ub::be_get_4(cipherKey +  4);
  rk[2] = ub::be_get_4(cipherKey +  8);
  rk[3] = ub::be_get_4(cipherKey + 12);
  for (;;)
  {
    temp  = rk[3];
    rk[4] = rk[0] ^
      (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
      (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
      (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
      (Te4[(temp >> 24)       ] & 0x000000ff) ^
      rcon[i];
    rk[5] = rk[1] ^ rk[4];
    rk[6] = rk[2] ^ rk[5];
    rk[7] = rk[3] ^ rk[6];
    if (++i == 10) return;
    rk += 4;
  }
}

void aesni_enc128_t::init(buf128_t key)
{
  uint32_t* s = (uint32_t*)sched;
  rijndael128KeySetupEnc(s, const_byte_ptr(&key));
  for (int i=0; i<44; i++)
  {
    uint32_t x = s[i];
    s[i] = ((x << 24) & 0xff000000 ) |
           ((x <<  8) & 0x00ff0000 ) |
           ((x >>  8) & 0x0000ff00 ) |
           ((x >> 24) & 0x000000ff );
  }
}

buf128_t aesni_enc128_t::encrypt(buf128_t in) const
{
  for (int i=0; i<9; i++)
  {
    in.value = vaeseq_u8(in.value, sched[i]);
    in.value = vaesmcq_u8(in.value);
  }
  in.value = vaeseq_u8(in.value, sched[9]);
  in.value ^= sched[10];
  return in;
}

void aesni_enc128_t::encrypt(buf128_t src1, buf128_t& dst1,
                             buf128_t src2, buf128_t& dst2,
                             buf128_t src3, buf128_t& dst3,
                             buf128_t src4, buf128_t& dst4) const
{
  dst1 = encrypt(src1);
  dst2 = encrypt(src2);
  dst3 = encrypt(src3);
  dst4 = encrypt(src4);
}

void aesni_enc128_t::encrypt(buf128_t src1, buf128_t& dst1,
                             buf128_t src2, buf128_t& dst2) const
{
  dst1 = encrypt(src1);
  dst2 = encrypt(src2);
}

bool aesni_enc128_t::supported() 
{
  return ub::cpuid::has_aes_ni();
}

#else
void aesni_enc128_t::init(buf128_t key)
{
  assert(false);
}

buf128_t aesni_enc128_t::encrypt(buf128_t in) const
{
  assert(false);
  return buf128_t(0);
}

void aesni_enc128_t::encrypt(buf128_t src1, buf128_t& dst1,
                          buf128_t src2, buf128_t& dst2,
                          buf128_t src3, buf128_t& dst3,
                          buf128_t src4, buf128_t& dst4) const
{
  assert(false);
}

void aesni_enc128_t::encrypt(buf128_t src1, buf128_t& dst1,
                             buf128_t src2, buf128_t& dst2) const
{
  assert(false);
}

bool aesni_enc128_t::supported() 
{
  return false;
}

#endif


// ---------------------------- aes_enc128_openssl_t ----------------------------

aes_enc128_openssl_t::~aes_enc128_openssl_t()
{
  if (ctx) EVP_CIPHER_CTX_free(ctx);
}

void aes_enc128_openssl_t::init(buf128_t key)
{
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit(ctx, EVP_aes_128_ecb(), const_byte_ptr(&key), NULL);
}

buf128_t aes_enc128_openssl_t::encrypt(buf128_t in) const
{
  buf128_t out;
  int out_size = AES_BLOCK_SIZE;
  EVP_CipherUpdate(ctx, byte_ptr(&out), &out_size, const_byte_ptr(&in), AES_BLOCK_SIZE);
  return out;
}

void aes_enc128_openssl_t::encrypt(buf128_t src1, buf128_t& dst1,
             buf128_t src2, buf128_t& dst2,
             buf128_t src3, buf128_t& dst3,
             buf128_t src4, buf128_t& dst4) const
{
  dst1 = encrypt(src1);
  dst2 = encrypt(src2);
  dst3 = encrypt(src3);
  dst4 = encrypt(src4);
}

void aes_enc128_openssl_t::encrypt(buf128_t src1, buf128_t& dst1,
               buf128_t src2, buf128_t& dst2) const
{
  dst1 = encrypt(src1);
  dst2 = encrypt(src2);
}

//----------------------------- aes_enc128_t ---------------------
  
aes_enc128_t::aes_enc128_t(bool use_aesni)
{
  mode_aesni = use_aesni && aesni_enc128_t::supported();
}

aes_enc128_t::aes_enc128_t(buf128_t key, bool use_aesni)
{
  mode_aesni = use_aesni && aesni_enc128_t::supported();
  init(key);
}

void aes_enc128_t::init(buf128_t key)
{
  if (mode_aesni) aesni.init(key);
  else openssl.init(key);
}

buf128_t aes_enc128_t::encrypt(buf128_t in) const
{
  if (mode_aesni) return aesni.encrypt(in);
  else return openssl.encrypt(in);
}

void aes_enc128_t::encrypt(buf128_t src1, buf128_t& dst1,
              buf128_t src2, buf128_t& dst2,
              buf128_t src3, buf128_t& dst3,
              buf128_t src4, buf128_t& dst4) const
{
  if (mode_aesni) return aesni.encrypt(src1, dst1, src2, dst2, src3, dst3, src4, dst4);
  else return openssl.encrypt(src1, dst1, src2, dst2, src3, dst3, src4, dst4);
}

void aes_enc128_t::encrypt(buf128_t src1, buf128_t& dst1, buf128_t src2, buf128_t& dst2) const
{
  if (mode_aesni) return aesni.encrypt(src1, dst1, src2, dst2);
  else return openssl.encrypt(src1, dst1, src2, dst2);
}

}