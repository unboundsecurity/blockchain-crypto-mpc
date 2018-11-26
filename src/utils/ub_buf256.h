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
#include "ub_buf128.h"

struct buf256_t
{
  buf128_t lo, hi; 

  buf256_t() {}
  buf256_t(null_ptr_t); // zeroization
  explicit buf256_t(mem_t src);

  buf256_t& operator= (mem_t src);
  buf256_t& operator= (null_ptr_t); // zeroization

  operator const_byte_ptr () const { return const_byte_ptr(this); }
  operator byte_ptr () { return byte_ptr(this); }
  operator mem_t() const { return mem_t(byte_ptr(this), sizeof(buf256_t)); }

  static buf256_t make(buf128_t half0, buf128_t half1=0);
  static buf256_t load(const_byte_ptr src);
  void save(byte_ptr dst) const;

  bool get_bit(int index) const;

  bool operator == (null_ptr_t) const;
  bool operator != (null_ptr_t) const;
  bool operator == (const buf256_t& src) const;
  bool operator != (const buf256_t& src) const;
  buf256_t operator ~ () const;
  buf256_t operator ^ (const buf256_t& src) const;
  buf256_t operator | (const buf256_t& src) const;
  buf256_t operator & (const buf256_t& src) const;
  buf256_t& operator ^= (const buf256_t& src);
  buf256_t& operator |= (const buf256_t& src);
  buf256_t& operator &= (const buf256_t& src);

  static buf256_t rand();
  void be_inc();

  buf256_t reverse_bytes() const;

  void convert(ub::converter_t& converter);
};

