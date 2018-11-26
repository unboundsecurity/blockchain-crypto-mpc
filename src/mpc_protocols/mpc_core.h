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
#include "ub_convert.h"

namespace mpc {

struct commitment_t
{
  buf128_t rand;
  buf256_t hash;

  void gen(const sha256_t& sha256);
  bool check(const sha256_t& sha256) const { return check(rand, hash, sha256); }
  static bool check(buf128_t rand, buf256_t hash, const sha256_t& sha256);
};

class agree_random_t
{
public:
  agree_random_t(int _size = 0) : size(_size) {}
  int size;
  buf256_t comm_hash;
  buf128_t comm_rand;
  buf_t agree1, agree2;

  void set_size(int _size) { size = _size; }

  void convert(ub::converter_t& converter)
  {
    converter.convert(size);
    converter.convert(comm_hash);
    converter.convert(comm_rand);
    converter.convert(agree1);
    converter.convert(agree2);
  }

  struct message1_t
  {
    buf256_t comm_hash;
    void convert(ub::converter_t& converter)
    {
      converter.convert(comm_hash);
    }
  };
  struct message2_t
  {
    buf_t agree2;
    void convert(ub::converter_t& converter)
    {
      converter.convert(agree2);
    }
  };
  struct message3_t
  {
    buf128_t comm_rand;
    buf_t agree1;
    void convert(ub::converter_t& converter)
    {
      converter.convert(comm_rand);
      converter.convert(agree1);
    }
  };

  void peer1_step1(message1_t& out);
  error_t peer2_step1(const message1_t& in, message2_t& out);
  error_t peer1_step2(const message2_t& in, message3_t& out, buf_t& result);
  error_t peer2_step2(const message3_t& in, buf_t& result);

  static buf_t generate(int size, mem_t agree1, mem_t agree2);
  static buf_t generate(int size, mem_t agree);
};

buf_t gen_shared_random(mem_t rnd1, mem_t rnd2, int out_size);




} //namespace mpc
