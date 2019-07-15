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
#include "ub_convert.h"
#include "mpc_core.h"

namespace mpc {

struct ot_sender_block_t
{
  buf128_t m0[128];
  buf128_t m1[128];

  void convert(ub::converter_t& converter)
  {
    converter.convert(m0);
    converter.convert(m1);
  }
};

struct ot_receiver_block_t
{
  buf128_t mb[128];
  buf128_t rnd;

  void convert(ub::converter_t& converter)
  {
    converter.convert(mb);
    converter.convert(rnd);
  }
};

struct ot_sender_info_t
{
  buf128_t m0, m1;

  void prepare_one_of_two(bool c, mem_t x0, mem_t x1, byte_ptr out);
  buf_t prepare_one_of_two(bool c, mem_t x0, mem_t x1);
};

struct ot_receiver_info_t
{
  bool r;
  buf128_t mb;

  void convert(ub::converter_t& converter)
  {
    converter.convert(r);
    converter.convert(mb);
  }

  void get_one_of_two(mem_t in, byte_ptr out);
  buf_t get_one_of_two(mem_t in);
};

struct ot_sender_t
{
  buf128_t delta;
  uint64_t counter;
  int index;
  crypto::ecb_aes_t ecb_keys_tb[128];
  buf128_t keys_tb[128];
  std::vector<ot_sender_block_t> blocks;
  
  void get_info(ot_sender_info_t& info);

  void convert(ub::converter_t& converter)
  {
    converter.convert(counter);
    converter.convert(index);
    converter.convert(blocks);
    converter.convert(delta);
    converter.convert(keys_tb);
    if (!converter.is_write())
    {
      for (int i=0; i<128; i++) { ecb_keys_tb[i].encrypt_init(mem_t(keys_tb[i])); }
    }
  }
};

struct ot_receiver_t
{
  uint64_t counter;
  int index;
  crypto::ecb_aes_t ecb_keys_t0[128];
  crypto::ecb_aes_t ecb_keys_t1[128];
  buf128_t keys_t0[128];
  buf128_t keys_t1[128];
  std::vector<ot_receiver_block_t> blocks;

  bool get_info(bool b, ot_receiver_info_t& info);
  
  void convert(ub::converter_t& converter)
  {
    converter.convert(counter);
    converter.convert(index);
    converter.convert(blocks);
    converter.convert(keys_t0);
    converter.convert(keys_t1);
    if (!converter.is_write())
    {
      for (int i=0; i<128; i++) { ecb_keys_t0[i].encrypt_init(mem_t(keys_t0[i])); ecb_keys_t1[i].encrypt_init(mem_t(keys_t1[i])); }
    }
  }
};

struct ot_base_init_t
{
  std::vector<ecc_point_t> Y;
  bn_t y[128];

  void convert(ub::converter_t& converter)
  {
    converter.convert(Y);
    converter.convert(y);
  }

  struct message1_t // rec -> snd
  {
    std::vector<ecc_point_t> Y;
    void convert(ub::converter_t& converter)
    {
      converter.convert(Y);
    }
  };

  struct message2_t // snd -> rec
  {
    std::vector<ecc_point_t> R;
    void convert(ub::converter_t& converter)
    {
      converter.convert(R);
    }
  };
  
  void rec_step1(ot_receiver_t& rec, message1_t& out);
  error_t snd_step2(ot_sender_t& snd, const message1_t& in, message2_t& out);
  error_t rec_step3(ot_receiver_t& rec, const message2_t& in);

  void clear();
};

struct ot_extend_t
{
  struct message1_t
  {
    ub::bufs128_t u;
    buf128_t x, t;
    void convert(ub::converter_t& converter)
    {
      converter.convert(u);
      converter.convert(x);
      converter.convert(t);
    }
  };

  void rec_step1(int blocks_count, ot_receiver_t& rec, message1_t& out); 
  error_t snd_step2(int blocks_count, ot_sender_t& snd, const message1_t& in);
};





} //namespace mpc