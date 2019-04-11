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

#include "mpc_crypto_ecdsa.h"
#include "mpc_crypto_generic_secret.h"
#include "mpc_ecdsa.h"
#include "mpc_ot.h"
#include "garbled_circuit_2party.h"

enum
{
  bip_sec_param = 64,
  bip_sec_count = bip_sec_param*2
};


class gcdef_bip_t : public circuit_def_t
{
public:
  gcdef_bip_t(int initial_seed_size, unsigned index);

  int opad_param, ipad_param, in1_param, in2_param, alpha1_param, alpha2_param;
  int q_param;
  int rho_param[bip_sec_count+1]; 
  int r1_param, r2_param;
  int out_c_par_param, out_r_param;
  int out_x2_param[bip_sec_count+1];

private:
  wires_t xor_gates(wires_t& in1, wires_t& in2);
  wires_t hmac(wires_t& opad_state, wires_t& ipad_state, wires_t& in);
  wires_t pad(wires_t& a);
  wires_t add(wires_t& a, wires_t& b);
  wires_t sub(wires_t& a, wires_t& b);
  int gt(wires_t& a, wires_t& b);
  wires_t add_mod(wires_t& a, wires_t& b, wires_t& m);
  wires_t sub_mod(wires_t& a, wires_t& b, wires_t& m);
  void set_const_4(wires_t& dst, int offset, unsigned value);
  void set_const_8(wires_t& dst, int offset, uint64_t value);

  wires_t bn_to_wires(const bn_t& value, int bits);
};

class mpc_ecdsa_derive_bip_t : public mpc_crypto_context_t
{
public:
  mpc_ecdsa_derive_bip_t() : hardened(false), initial(true), child_index(0), old_bip_level(0), old_c_par(0), new_parent_fingerprint(0), new_c_par(0), 
    gc_initialized(false), circuit_def(nullptr), mpc_circuit_def(nullptr), agree_random(16) {}

  ~mpc_ecdsa_derive_bip_t()
  {
    delete mpc_circuit_def;
  }

  static const uint64_t CODE_TYPE = 0xa5be406795b76416;
  virtual uint64_t get_type() const { return CODE_TYPE; }

  virtual void convert(ub::converter_t& converter) override;
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags) override
  {
    return protocol_step(*this, in, out, flags);
  }

  virtual mpc_crypto_key_e get_share_type() const override { return initial ? mpc_generic_secret : mpc_ecdsa; }
  virtual mpc_crypto_share_t* create_share() const override { return initial ? (mpc_crypto_share_t*)new mpc_generic_secret_share_t : (mpc_crypto_share_t*)new mpc_ecdsa_share_t; }

  error_t init(bool hardened, unsigned index, const mpc_ecdsa_share_t& ecdsa_share);
  error_t init(const mpc_generic_secret_share_t& seed_share);
  error_t get_result_share(mpc_crypto_share_t*& result_share) const;

  virtual void get_share_core(mpc_crypto_share_t& dst) const override;
  virtual void set_share_core(const mpc_crypto_share_t& src) override;
  virtual int get_messages_count() const override;
  virtual bool changes_share() const override { return false; }

  error_t party1_step1(none_message_t& out);

  struct message1_t 
  {
    mpc::ot_base_init_t::message1_t ot_base_init1_msg1;
    void convert(ub::converter_t& converter)
    {
      converter.convert(ot_base_init1_msg1);
    }
  };

  struct message2_t 
  {
    mpc::ot_base_init_t::message2_t ot_base_init1_msg2;
    mpc::ot_base_init_t::message1_t ot_base_init2_msg1;

    void convert(ub::converter_t& converter)
    {
      converter.convert(ot_base_init1_msg2);
      converter.convert(ot_base_init2_msg1);
    }
  };

  struct message3_t 
  {
    mpc::ot_base_init_t::message2_t ot_base_init2_msg2;
    mpc::ot_extend_t::message1_t ot_extend1_msg1;
    gc_2party_t::message1_t gc_msg1;

    void convert(ub::converter_t& converter)
    {
      converter.convert(ot_base_init2_msg2);
      converter.convert(ot_extend1_msg1);
      converter.convert(gc_msg1);
    }
  };

  struct message4_t 
  {
    mpc::ot_extend_t::message1_t ot_extend2_msg1;
    gc_2party_t::message2_t gc_msg2;
    mpc::agree_random_t::message1_t agree_msg1;

    void convert(ub::converter_t& converter)
    {
      converter.convert(ot_extend2_msg1);
      converter.convert(gc_msg2);
      converter.convert(agree_msg1);
    }
  };

  struct message5_t 
  {
    gc_2party_t::message3_t gc_msg3;
    mpc::agree_random_t::message2_t agree_msg2;
    void convert(ub::converter_t& converter)
    {
      converter.convert(agree_msg2);
      converter.convert(gc_msg3);
    }
  };

  struct message6_t
  {
    mpc::agree_random_t::message3_t agree_msg3;
    gc_2party_t::message4_t gc_msg4;
    buf256_t comm_Q2_hash;
    ecc_point_t Q2_first;
    void convert(ub::converter_t& converter)
    {
      converter.convert(comm_Q2_hash);
      converter.convert(Q2_first);
      converter.convert(gc_msg4);
      converter.convert(agree_msg3);
    }
  };

  struct message7_t 
  {
    gc_2party_t::message5_t gc_msg5;
    std::vector<ecc_point_t> Q1;
    mpc::ecdsa_generate_t::message1_t gen_msg1;

    void convert(ub::converter_t& converter)
    {
      converter.convert(gc_msg5);
      converter.convert(Q1);
      converter.convert(gen_msg1);
    }
  };
  
  struct message8_t 
  {
    buf128_t comm_Q2_rand;
    std::vector<ecc_point_t> Q2;
    mpc::ecdsa_generate_t::message2_t gen_msg2;

    void convert(ub::converter_t& converter)
    {
      converter.convert(gen_msg2);
      converter.convert(comm_Q2_rand);
      converter.convert(Q2);
    }
  };

  typedef  mpc::ecdsa_generate_t::message3_t message9_t ;

  error_t party1_step1 (message1_t& out);
  error_t party2_step1 (const message1_t& in,  message2_t& out);
  error_t party1_step2 (const message2_t& in,  message3_t& out);
  error_t party2_step2 (const message3_t& in,  message4_t& out);
  error_t party1_step3 (const message4_t& in,  message5_t& out);
  error_t party2_step3 (const message5_t& in,  message6_t& out);
  error_t party1_step4 (const message6_t& in,  message7_t& out);
  error_t party2_step4 (const message7_t& in,  message8_t& out);
  error_t party1_step5 (const message8_t& in,  message9_t& out);
  error_t party2_step5 (const message9_t& in,  none_message_t& out);

private:
  bool hardened;
  bool initial;
  unsigned child_index;

  mpc::ecdsa_share_t new_share;
  unsigned new_parent_fingerprint;
  buf256_t new_c_par;
  
  buf_t old_seed_share;
  mpc::ecdsa_share_t old_ecdsa_share;
  uint8_t old_bip_level;
  buf256_t old_c_par;

  mpc::ot_sender_t ot_sender;
  mpc::ot_receiver_t ot_receiver;
  mpc::ot_base_init_t ot_base_init_sender;
  mpc::ot_base_init_t ot_base_init_receiver;
  mpc::ot_extend_t ot_extend_sender;
  mpc::ot_extend_t ot_extend_receiver;

  bool gc_initialized;
  gc_2party_t gc;
  std::vector<bn_t> rho;
  ub::bits_t alpha1, alpha2;

  bn_t r;
  std::vector<bn_t> new_x;
  std::vector<ecc_point_t> Q1;
  std::vector<ecc_point_t> Q2;
  buf128_t comm_Q2_rand;
  buf256_t comm_Q2_hash;
  mpc::ecdsa_generate_t gen_helper;
  mpc::agree_random_t agree_random;
  buf_t session_id;

  const gcdef_bip_t* circuit_def;
  mpc_circuit_def_t* mpc_circuit_def;

  error_t execute_normal_derivation();
  void init_circuit_def();
  error_t check_new_Q();

  void gc_init_peer1();
  void gc_init_peer2();
};

static ub::convertable_t::factory_t::register_t<mpc_ecdsa_derive_bip_t, mpc_ecdsa_derive_bip_t::CODE_TYPE> g_register_mpc_ecdsa_derive_bip_t;



