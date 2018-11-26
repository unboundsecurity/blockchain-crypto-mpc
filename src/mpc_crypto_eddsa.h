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

#include "mpc_eddsa.h"
#include "mpc_crypto_context.h"
#include "mpc_core.h"

class mpc_eddsa_share_t : public mpc_crypto_share_t
{
public:
  static const uint64_t CODE_TYPE = 0xd68c71663a9a4dcc;
  mpc_eddsa_share_t();
  virtual void convert(ub::converter_t& converter) override;
  virtual mpc_crypto_key_e get_type() const override { return mpc_eddsa; }
  void copy_pub_key(byte_ptr out) const { core.Q_full.encode(out); }
  virtual mpc_crypto_context_t* create_refresh_oper();
  
  virtual uint64_t calc_uid() const override 
  { 
    byte_t pub_key[32];
    core.Q_full.encode(pub_key);
    return crypto::sha256_truncated_uint64(mem_t(pub_key, 32)); 
  }

  mpc::eddsa_share_t core;
};
static ub::convertable_t::factory_t::register_t<mpc_eddsa_share_t, mpc_eddsa_share_t::CODE_TYPE> g_register_mpc_eddsa_share_t;

class mpc_eddsa_refresh_t : public mpc_crypto_context_t
{
public:
  static const uint64_t CODE_TYPE = 0x81b6d0d69a7f4f48;

  mpc_eddsa_refresh_t() : agree_random(64*3+1) {}

  virtual uint64_t get_type() const override { return CODE_TYPE; }
  virtual void convert(ub::converter_t& converter) override;
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags) override
  {
    return protocol_step(*this, in, out, flags);
  }

  virtual mpc_crypto_share_t* create_share() const override { return new mpc_eddsa_share_t; }
  virtual mpc_crypto_key_e get_share_type() const override { return mpc_eddsa; }

  virtual void set_share_core(const mpc_crypto_share_t& src) override { share = ((const mpc_eddsa_share_t&)src).core;}
  virtual void get_share_core(mpc_crypto_share_t& dst) const { ((mpc_eddsa_share_t&)dst).core = share; }

  virtual int get_messages_count() const override { return 3; }
  virtual bool changes_share() const override { return true; }

  typedef mpc::agree_random_t::message1_t message1_t;
  typedef mpc::agree_random_t::message2_t message2_t;
  typedef mpc::agree_random_t::message3_t message3_t;
  
  error_t party1_step1(message1_t& out);
  error_t party2_step1(const message1_t& in, message2_t& out);
  error_t party1_step2(const message2_t& in, message3_t& out);
  error_t party2_step2(const message3_t& in, none_message_t& out);

private:
  mpc::eddsa_share_t share;
  mpc::agree_random_t agree_random;

};
static ub::convertable_t::factory_t::register_t<mpc_eddsa_refresh_t, mpc_eddsa_refresh_t::CODE_TYPE> g_register_mpc_eddsa_refresh_t;

class mpc_eddsa_gen_t : public mpc_crypto_context_t
{
public:
  mpc_eddsa_gen_t();

  static const uint64_t CODE_TYPE = 0xf8e9471543464fc2;
  virtual uint64_t get_type() const override { return CODE_TYPE; }
  virtual mpc_crypto_key_e get_share_type() const override { return mpc_eddsa; }

  virtual void convert(ub::converter_t& converter) override;
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags) override
  {
    return protocol_step(*this, in, out, flags);
  }
  
  virtual mpc_crypto_share_t* create_share() const override { return new mpc_eddsa_share_t; }
  virtual void set_share_core(const mpc_crypto_share_t& src) override { assert(false); }
  virtual void get_share_core(mpc_crypto_share_t& dst) const { ((mpc_eddsa_share_t&)dst).core = share; }
  
  virtual int get_messages_count() const override { return 6; }
  virtual bool changes_share() const override { return true; }

  typedef mpc::agree_random_t::message1_t message1_t;
  typedef mpc::agree_random_t::message2_t message2_t;

  struct message3_t
  {
    mpc::agree_random_t::message3_t agree_msg3;
    mpc::eddsa_gen_t::message1_t gen_msg1;
    void convert(ub::converter_t& converter)
    {
      converter.convert(agree_msg3);
      converter.convert(gen_msg1);
    }
  };

  typedef mpc::eddsa_gen_t::message2_t message4_t;
  typedef mpc::eddsa_gen_t::message3_t message5_t;
  typedef mpc::eddsa_gen_t::message4_t message6_t;

  error_t party1_step1(message1_t& out);
  error_t party2_step1(const message1_t& in, message2_t& out);
  error_t party1_step2(const message2_t& in, message3_t& out);
  error_t party2_step2(const message3_t& in, message4_t& out);
  error_t party1_step3(const message4_t& in, message5_t& out);
  error_t party2_step3(const message5_t& in, message6_t& out);
  error_t party1_step4(const message6_t& in, none_message_t& out);

private:
  mpc::eddsa_share_t share;
  mpc::eddsa_gen_t ctx;
  mpc::agree_random_t agree_random;

};
static ub::convertable_t::factory_t::register_t<mpc_eddsa_gen_t, mpc_eddsa_gen_t::CODE_TYPE> g_register_mpc_eddsa_gen_t;

class mpc_eddsa_sign_t : public mpc_crypto_context_t
{
public:
  static const uint64_t CODE_TYPE = 0xa6987b06a1664ccd;
  virtual uint64_t get_type() const { return CODE_TYPE; }
  mpc_eddsa_sign_t();
  virtual void convert(ub::converter_t& converter) override;
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags) override
  {
    return protocol_step(*this, in, out, flags);
  }

  virtual mpc_crypto_share_t* create_share() const override { return new mpc_eddsa_share_t; }
  virtual void set_share_core(const mpc_crypto_share_t& src) override { share = ((const mpc_eddsa_share_t&)src).core;}
  virtual void get_share_core(mpc_crypto_share_t& dst) const { ((mpc_eddsa_share_t&)dst).core = share; }

  void copy_result(byte_ptr out) const { memmove(out, result, 64); }
  void set_data_to_sign(mem_t data_to_sign) { ctx.data_to_sign = data_to_sign; }
  void set_refresh(bool refresh) { this->refresh = refresh; }
  virtual mpc_crypto_key_e get_share_type() const override { return mpc_eddsa; }

  virtual int get_messages_count() const override { return 6; }
  virtual bool changes_share() const override { return refresh; }

  struct message1_t
  {
    mpc::eddsa_sign_t::message1_t sign_msg1;
    bool refresh;
    buf_t data_to_sign;

    void convert(ub::converter_t& converter)
    {
      converter.convert(sign_msg1);
      converter.convert(refresh);
      converter.convert(data_to_sign);
    }
  };

  typedef mpc::eddsa_sign_t::message2_t message2_t;
  typedef mpc::eddsa_sign_t::message3_t message3_t;
  typedef mpc::eddsa_sign_t::message4_t message4_t;
  typedef mpc::eddsa_sign_t::message5_t message5_t;
  typedef mpc::eddsa_sign_t::message6_t message6_t;

  error_t party1_step1(message1_t& out);
  error_t party2_step1(const message1_t& in, message2_t& out);
  error_t party1_step2(const message2_t& in, message3_t& out);
  error_t party2_step2(const message3_t& in, message4_t& out);
  error_t party1_step3(const message4_t& in, message5_t& out);
  error_t party2_step3(const message5_t& in, message6_t& out);
  error_t party1_step4(const message6_t& in, none_message_t& out);

private:
  bool refresh;
  mpc::eddsa_sign_t ctx;
  byte_t result[64];
  mpc::eddsa_share_t share;
};
static ub::convertable_t::factory_t::register_t<mpc_eddsa_sign_t, mpc_eddsa_sign_t::CODE_TYPE> g_register_mpc_eddsa_sign_t;
