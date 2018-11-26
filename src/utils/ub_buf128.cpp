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
#include "crypto.h"

using namespace ub;

bool buf128_t::operator == (null_ptr_t null_ptr) const { return *this==buf128_t(null_ptr); }
bool buf128_t::operator != (null_ptr_t null_ptr) const { return *this!=buf128_t(null_ptr); }

buf128_t::buf128_t (null_ptr_t null_ptr)
{
#if defined(INTEL_X64)
  value = _mm_setzero_si128();
#elif defined(__aarch64__)
  value = vcombine_u8(uint64x1_t(uint64_t(0)),uint64x1_t(uint64_t(0)));
#elif defined(__LITTLE_ENDIAN__)
  lo = hi = 0;
#else
  memset(this, 0, sizeof(buf128_t))
#endif
}

buf128_t& buf128_t::operator= (null_ptr_t) // zeroization
{
  return *this = buf128_t(0);
}

buf128_t buf128_t::load(const_byte_ptr src)
{
  buf128_t dst;
#if defined(INTEL_X64)
  dst.value = _mm_loadu_si128((__m128i*)src);
#elif defined(__aarch64__)
  dst.value = vld1q_u8(src);
#elif defined(__LITTLE_ENDIAN__)
  dst.lo = ((uint64_t*)src)[0];
  dst.hi = ((uint64_t*)src)[1];
#else
  memmove(dst.data, src, 16);
#endif
  return dst;
}


buf128_t::buf128_t(mem_t src)
{
  assert(src.size==sizeof(buf128_t));
  *this = load(src.data);
}

buf128_t& buf128_t::operator= (mem_t src)
{
  assert(src.size==sizeof(buf128_t));
  return *this = load(src.data);
}


uint64_t buf128_t::le_half0() const
{
#if defined(INTEL_X64)
  return _mm_cvtsi128_si64(value);
#elif defined(__aarch64__)
  return ((uint64_t*)this)[0];
#elif defined(__LITTLE_ENDIAN__)
  return lo;
#else
  return le_get_8(data);
#endif
}

uint64_t buf128_t::le_half1() const
{
#if defined(INTEL_X64)
  return _mm_cvtsi128_si64(_mm_srli_si128(value, 8));
#elif defined(__aarch64__)
  return ((uint64_t*)this)[1];
#elif defined(__LITTLE_ENDIAN__)
  return hi;
#else
  return le_get_8(data+8);
#endif
}

uint64_t buf128_t::be_half0() const
{
  return be_get_8(byte_ptr(this));
}

uint64_t buf128_t::be_half1() const
{
  return be_get_8((byte_ptr(this))+8);
}

void buf128_t::save(byte_ptr dst) const
{
#if defined(INTEL_X64)
  _mm_storeu_si128((__m128i*)dst, value);
#elif defined(__aarch64__)
  vst1q_u8(dst, value);
#elif defined(__LITTLE_ENDIAN__)
  ((uint64_t*)dst)[0] = lo;
  ((uint64_t*)dst)[1] = hi;
#else
  memmove(dst, data, 16);
#endif
}

buf128_t buf128_t::make_le(uint64_t part0, uint64_t part1) // static 
{
  buf128_t o;
#if defined(INTEL_X64)
  o.value = _mm_set_epi64x(part1, part0);
#elif defined(__aarch64__)
  o.value = vcombine_u8(uint64x1_t(part0),uint64x1_t(part1));
#elif defined(__LITTLE_ENDIAN__)
  o.lo = part0;
  o.hi = part1;
#else
  le_set_8(o.data, part0);
  le_set_8(o.data+8, part1);
#endif
  return o;
}

buf128_t buf128_t::make_be(uint64_t part0, uint64_t part1) // static 
{
  buf128_t o;
  be_set_8(&o[0], part0);
  be_set_8(&o[8], part1);
  return o;
}

bool buf128_t::get_bit(int index) const
{
#ifdef __LITTLE_ENDIAN__
  int n = index / 64;
  index %= 64;
  return ((((const uint64_t*)(this))[n] >> index) & 1) != 0;
#else
  int n = index / 8;
  index %= 8;
  return ((data[n] >> index) & 1) != 0;
#endif
}

#if defined(INTEL_X64)
static uint16_t oword_cmp_mask(__m128i a, __m128i b)
{
  __m128i vcmp = _mm_cmpeq_epi8(a, b);       // PCMPEQB
  return _mm_movemask_epi8(vcmp);            // PMOVMSKB
}
#endif


bool buf128_t::operator == (const buf128_t& src) const
{
#if defined(INTEL_X64)
  return oword_cmp_mask(value, src.value)==0xffff;
#elif defined(__aarch64__)
  return 0==memcmp(this, &src, sizeof(buf128_t));
#elif defined(__LITTLE_ENDIAN__)
  return lo==src.lo && hi==src.hi;
#else
  return 0==memcmp(data, src.data, sizeof(buf128_t));
#endif
}

bool buf128_t::operator != (const buf128_t& src) const
{
#if defined(INTEL_X64)
  return oword_cmp_mask(value, src.value)!=0xffff;
#elif defined(__aarch64__)
  return 0!=memcmp(this, &src, sizeof(buf128_t));
#elif defined(__LITTLE_ENDIAN__)
  return lo!=src.lo || hi!=src.hi;
#else
  return 0!=memcmp(data, src.data, sizeof(buf128_t));
#endif
}

buf128_t buf128_t::operator ~ () const
{
  buf128_t dst;
#if defined(INTEL_X64)
  dst.value = _mm_xor_si128(value, _mm_set1_epi32(-1));
#elif defined(__aarch64__)
  ((uint64_t*)&dst)[0] = ~((uint64_t*)this)[0];
  ((uint64_t*)&dst)[1] = ~((uint64_t*)this)[1];
#elif defined(__LITTLE_ENDIAN__)
  dst.lo = ~lo;
  dst.hi = ~hi;
#else
  ((uint64_t*)&dst)[0] = ~((uint64_t*)this)[0];
  ((uint64_t*)&dst)[1] = ~((uint64_t*)this)[1];
#endif
  return dst;
}

buf128_t buf128_t::operator ^ (const buf128_t& src) const 
{ 
  buf128_t dst; 
#if defined(INTEL_X64)
  dst.value = _mm_xor_si128(value, src.value);
#elif defined(__aarch64__)
  dst.value = value ^ src.value;
#elif defined(__LITTLE_ENDIAN__)
  dst.lo = lo ^ src.lo;
  dst.hi = hi ^ src.hi;
#else
  ((uint64_t*)&dst)[0] = ((uint64_t*)this)[0] ^ ((uint64_t*)&src)[0];
  ((uint64_t*)&dst)[1] = ((uint64_t*)this)[1] ^ ((uint64_t*)&src)[1];
#endif
  return dst; 
}

buf128_t buf128_t::operator | (const buf128_t& src) const 
{ 
  buf128_t dst; 
#if defined(INTEL_X64)
  dst.value = _mm_or_si128(value, src.value);
#elif defined(__aarch64__)
  dst.value = value | src.value;
#elif defined(__LITTLE_ENDIAN__)
  dst.lo = lo | src.lo;
  dst.hi = hi | src.hi;
#else
  ((uint64_t*)&dst)[0] = ((uint64_t*)this)[0] | ((uint64_t*)&src)[0];
  ((uint64_t*)&dst)[1] = ((uint64_t*)this)[1] | ((uint64_t*)&src)[1];
#endif
  return dst; 
}

buf128_t buf128_t::operator & (const buf128_t& src) const 
{ 
  buf128_t dst; 
#if defined(INTEL_X64)
  dst.value = _mm_and_si128(value, src.value);
#elif defined(__aarch64__)
  dst.value = value & src.value;
#elif defined(__LITTLE_ENDIAN__)
  dst.lo = lo & src.lo;
  dst.hi = hi & src.hi;
#else
  ((uint64_t*)&dst)[0] = ((uint64_t*)this)[0] & ((uint64_t*)&src)[0];
  ((uint64_t*)&dst)[1] = ((uint64_t*)this)[1] & ((uint64_t*)&src)[1];
#endif
  return dst; 
}

buf128_t& buf128_t::operator ^= (const buf128_t& src) { return *this = *this ^ src; }
buf128_t& buf128_t::operator |= (const buf128_t& src) { return *this = *this | src; }
buf128_t& buf128_t::operator &= (const buf128_t& src) { return *this = *this & src; }

void buf128_t::be_inc()
{
  byte_ptr p = byte_ptr(this) + 16;
  for (int i=0; i<16; i++)
  {
    byte_t x = *--p;
    *p = ++x;
    if (x) break;
  }
}

buf128_t buf128_t::reverse_bytes() const
{
  buf128_t out;
  byte_ptr dst = &out[0];
  const_byte_ptr src = byte_ptr(this) + 16;
  for (int i=0; i<16; i++) *dst++ = *--src;
  return out;
}

buf128_t buf128_t::rand()
{
  buf128_t out;
  crypto::gen_random(mem_t(out));
  return out;
}

void buf128_t::convert(ub::converter_t& converter)
{
  if (converter.is_write())
  {
    if (!converter.is_calc_size()) save(converter.current());
  }
  else
  {
    if (converter.is_error() || !converter.at_least(16)) { converter.set_error(); return; }
    *this = load(converter.current());
  }
  converter.forward(16);
}



namespace ub {
// -------------------------- ub::bufs128_t ---------------------------

//move ct'or
bufs128_t::bufs128_t(bufs128_t &&src) : v(std::move(src.v))
{ 
}

//move assignment
bufs128_t& bufs128_t::operator= (bufs128_t&& src) 
{ 
  if (&src!=this)
  {
    v = std::move(src.v);
  }
  return *this;
}

bool bufs128_t::operator == (const bufs128_t& other) const
{
  return v == other.v;
}

bool bufs128_t::operator != (const bufs128_t& other) const
{
  return v != other.v;
}

bufs128_t& bufs128_t::operator= (const bufs128_t& src)
{
  v = src.v;
  return *this;
}

void bufs128_t::save(byte_ptr out) const
{
  memmove(out, data(), size()*sizeof(buf128_t));
}

void bufs128_t::load(mem_t src)
{
  memmove(allocate(src.size/sizeof(buf128_t)), src.data, src.size);
}

void bufs128_t::convert(ub::converter_t& converter)
{
  int count = size();
  converter.convert(count);
  int data_size = count*sizeof(buf128_t);
  
  if (converter.is_write())
  {
    if (!converter.is_calc_size()) memmove(converter.current(), data(), data_size);
  }
  else
  {
    if (converter.is_error() || !converter.at_least(count*sizeof(buf128_t))) { converter.set_error(); return; }
    memmove(allocate(count), converter.current(), data_size);
  }
  converter.forward(data_size);
}

} //namespace ub
