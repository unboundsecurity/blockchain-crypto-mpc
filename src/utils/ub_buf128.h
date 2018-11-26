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
#include "ub_common_def.h"

namespace ub
{
  class converter_t;
}

struct buf128_t
{
#if defined(INTEL_X64)
  __m128i value;
#elif defined(__aarch64__)
  uint8x16_t value;
#elif defined(__LITTLE_ENDIAN__)
  uint64_t lo, hi;
#else
  byte_t data[16];
#endif

  buf128_t() {}
  buf128_t (null_ptr_t); // zeroization
  explicit buf128_t(mem_t src);

  operator mem_t() const { return mem_t(byte_ptr(this), sizeof(buf128_t)); }
  buf128_t& operator = (null_ptr_t); // zeroization
  buf128_t& operator = (mem_t); 
  
  operator const_byte_ptr () const { return const_byte_ptr(this); }
  operator byte_ptr () { return byte_ptr(this); }

  uint64_t le_half0() const;
  uint64_t le_half1() const;
  uint64_t be_half0() const;
  uint64_t be_half1() const;

  static buf128_t make_le(uint64_t half0, uint64_t half1=0);
  static buf128_t make_be(uint64_t half0, uint64_t half1=0);
  
  static buf128_t load(const_byte_ptr src); 
  void save(byte_ptr dst) const;

  bool get_bit(int index) const;

  bool operator == (null_ptr_t) const;
  bool operator != (null_ptr_t) const;
  bool operator == (const buf128_t& src) const;
  bool operator != (const buf128_t& src) const;
  buf128_t operator ~ () const;
  buf128_t operator ^ (const buf128_t& src) const;
  buf128_t operator | (const buf128_t& src) const;
  buf128_t operator & (const buf128_t& src) const;
  buf128_t& operator ^= (const buf128_t& src);
  buf128_t& operator |= (const buf128_t& src);
  buf128_t& operator &= (const buf128_t& src);

  static buf128_t rand();

  void be_inc();

  buf128_t reverse_bytes() const;
  
  byte_t operator[] (int index) const { return (byte_ptr(this))[index]; }
  byte_t& operator[] (int index) { return (byte_ptr(this))[index]; }

  void convert(ub::converter_t& converter);

};

namespace ub {


class bufs128_t //: public convertable_t
{
public:
  bufs128_t() { }
  explicit bufs128_t(int size) : v(size) {}
  bufs128_t(mem_t src);
  bufs128_t(const bufs128_t& src) : v(src.v) { }
  bufs128_t(bufs128_t &&src); //move ct'or
  ~bufs128_t() { free(); }
  void free() { mem().secure_bzero(); v.clear(); }
  bool empty() const { return v.empty(); }
  int size() const { return (int)v.size(); }
  buf128_t* data() { return empty() ? nullptr : &v[0]; }
  const buf128_t* data() const { return empty() ? nullptr : &v[0]; }
  buf128_t* allocate(int size) { v.resize(size); return data(); }

  bufs128_t& operator= (const bufs128_t& src);
  bufs128_t& operator= (bufs128_t&& src);  //move assignment

  const buf128_t& operator [] (int index) const { return v[index]; }
  buf128_t& operator [] (int index) { return v[index]; }
  mem_t mem() const { return mem_t(const_byte_ptr(data()), int(v.size()*sizeof(buf128_t))); }
  operator mem_t () const { return mem(); }

  bool operator == (const bufs128_t& other) const;
  bool operator != (const bufs128_t& other) const;
  void save(byte_ptr out) const;
  void load(mem_t src);

  //virtual void convert(ub::converter_t& converter);
  void convert(converter_t& converter);

private:
  std::vector<buf128_t> v;
};

} // namespace
