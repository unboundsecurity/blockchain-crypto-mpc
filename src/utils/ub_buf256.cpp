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
#include "ub_common.h"
#include "ub_buf256.h"
#include "crypto.h"

buf256_t& buf256_t::operator = (mem_t src)
{
  assert(src.size==sizeof(buf256_t));
  return *this = load(src.data);
}


buf256_t::buf256_t(mem_t src)
{
  assert(src.size==sizeof(buf256_t));
  *this = load(src.data);
}


buf256_t::buf256_t(null_ptr_t)
{
  lo = hi = 0;
}

buf256_t& buf256_t::operator= (null_ptr_t) // zeroization
{
  lo = hi = 0;
  return *this;
}

bool buf256_t::operator == (null_ptr_t null_ptr) const { return *this==buf256_t(null_ptr); }
bool buf256_t::operator != (null_ptr_t null_ptr) const { return *this!=buf256_t(null_ptr); }


buf256_t buf256_t::make(buf128_t half0, buf128_t half1)
{
  buf256_t dst;
  dst.lo = half0;
  dst.hi = half1;
  return dst;
}

buf256_t buf256_t::load(const_byte_ptr src) // static
{
  buf256_t dst;
  dst.lo = buf128_t::load(src);
  dst.hi = buf128_t::load(src+16);
  return dst;
}

void buf256_t::save(byte_ptr dst) const
{
  lo.save(dst);
  hi.save(dst+16);
}

bool buf256_t::get_bit(int index) const
{
#ifdef __LITTLE_ENDIAN__
  int n = index / 64;
  index %= 64;
  return ((((const uint64_t*)(this))[n] >> index) & 1) != 0;
#else
  int n = index / 8;
  index %= 8;
  return (((const_byte_ptr(this))[n] >> index) & 1) != 0;
#endif
}

bool buf256_t::operator == (const buf256_t& src) const
{
  return (src.lo == lo) && (src.hi == hi);
}

bool buf256_t::operator != (const buf256_t& src) const
{
  return (src.lo != lo) || (src.hi != hi);
}

buf256_t buf256_t::operator ~ () const
{
  buf256_t dst;
  dst.lo = ~lo;
  dst.hi = ~hi;
  return dst;
}

buf256_t buf256_t::operator ^ (const buf256_t& src) const
{
  buf256_t dst; 
  dst.lo = lo ^ src.lo;
  dst.hi = hi ^ src.hi;
  return dst; 
}

buf256_t buf256_t::operator | (const buf256_t& src) const
{
  buf256_t dst; 
  dst.lo = lo | src.lo;
  dst.hi = hi | src.hi;
  return dst; 
}

buf256_t buf256_t::operator & (const buf256_t& src) const
{
  buf256_t dst; 
  dst.lo = lo & src.lo;
  dst.hi = hi & src.hi;
  return dst; 
}

buf256_t& buf256_t::operator ^= (const buf256_t& src)  { return *this = *this ^ src; }
buf256_t& buf256_t::operator |= (const buf256_t& src)  { return *this = *this | src; }
buf256_t& buf256_t::operator &= (const buf256_t& src)  { return *this = *this & src; }

void buf256_t::be_inc()
{
  byte_ptr p = byte_ptr(this) + 32;
  for (int i=0; i<32; i++)
  {
    byte_t x = *--p;
    *p = ++x;
    if (x) break;
  }
}

buf256_t buf256_t::reverse_bytes() const
{
  buf256_t out;
  byte_ptr dst = byte_ptr(&out);
  const_byte_ptr src = const_byte_ptr(this) + 32;
  for (int i=0; i<32; i++) *dst++ = *--src;
  return out;
}

buf256_t buf256_t::rand()
{
  buf256_t out;
  crypto::gen_random(mem_t(out));
  return out;
}

void buf256_t::convert(ub::converter_t& converter)
{
  if (converter.is_write())
  {
    if (!converter.is_calc_size()) save(converter.current());
  }
  else
  {
    if (converter.is_error() || !converter.at_least(32)) { converter.set_error(); return; }
    *this = load(converter.current());
  }
  converter.forward(32);
}

