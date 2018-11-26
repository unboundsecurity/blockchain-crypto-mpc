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
#include "mpc_crypto_context.h"
#include "mpc_ecdsa.h"
#include "ecc_backup.h"


class mpc_ecdsa_share_t : public mpc_crypto_share_t
{
public:
  static const uint64_t CODE_TYPE = 0xec56c8758dff402e;
  virtual void convert(ub::converter_t& converter) override;
  virtual mpc_crypto_key_e get_type() const override { return mpc_ecdsa; }
  virtual mpc_crypto_context_t* create_refresh_oper();
  
  virtual uint64_t calc_uid() const override { return crypto::sha256_truncated_uint64(core.Q_full.to_der()); }

  void get_bip_info(bip32_info_t& bip_info) const;

  mpc::ecdsa_share_t core;

  struct bip_t
  {
    bip_t() : level(0), c_par(0), hardened(false), child_number(0), parent_fingerprint(0) {}
    bool hardened;
    uint8_t level;
    uint32_t child_number;
    uint32_t parent_fingerprint;
    buf256_t c_par;

    void convert(ub::converter_t& converter)
    {
      converter.convert(level);
      if (level)
      {
        converter.convert(hardened);
        converter.convert(child_number);
        converter.convert(parent_fingerprint);
      }
      converter.convert(c_par);
    }
  };

  bip_t bip;
};
static ub::convertable_t::factory_t::register_t<mpc_ecdsa_share_t, mpc_ecdsa_share_t::CODE_TYPE> g_register_mpc_ecdsa_share_t;

class mpc_ecdsa_refresh_t : public mpc_crypto_context_t
{
public:
  static const uint64_t CODE_TYPE = 0xa8254933a6597418;

  virtual uint64_t get_type() const override { return CODE_TYPE; }
  virtual void convert(ub::converter_t& converter) override;
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags) override
  {
    return protocol_step(*this, in, out, flags);
  }

  virtual mpc_crypto_share_t* create_share() const override { return new mpc_ecdsa_share_t; }
  virtual mpc_crypto_key_e get_share_type() const override { return mpc_ecdsa; }
  virtual void get_share_core(mpc_crypto_share_t& dst) const 
  { 
    ((mpc_ecdsa_share_t&)dst).core = share; 
    ((mpc_ecdsa_share_t&)dst).bip = bip; 
  }

  virtual void set_share_core(const mpc_crypto_share_t& src) override 
  { 
    share = ((const mpc_ecdsa_share_t&)src).core; 
    bip = ((const mpc_ecdsa_share_t&)src).bip; 
  }

  virtual int get_messages_count() const override { return 3; }
  virtual bool changes_share() const override { return true; }

  typedef mpc::ecdsa_refresh_t::message1_t message1_t;
  typedef mpc::ecdsa_refresh_t::message2_t message2_t;
  typedef mpc::ecdsa_refresh_t::message3_t message3_t;


  error_t party1_step1(message1_t& out);
  error_t party2_step1(const message1_t& in, message2_t& out);
  error_t party1_step2(const message2_t& in, message3_t& out);
  error_t party2_step2(const message3_t& in, none_message_t& out);

private:
  mpc::ecdsa_share_t share;
  mpc_ecdsa_share_t::bip_t bip;
  mpc::ecdsa_refresh_t refresh;
};
static ub::convertable_t::factory_t::register_t<mpc_ecdsa_refresh_t, mpc_ecdsa_refresh_t::CODE_TYPE> g_register_mpc_ecdsa_refresh_t;

class mpc_ecdsa_gen_t : public mpc_crypto_context_t
{
public:
  mpc_ecdsa_gen_t() : curve(nullptr), agree_random(32) {}

  static const uint64_t CODE_TYPE = 0xd8269cef207c4fbf;
  virtual uint64_t get_type() const override { return CODE_TYPE; }

  virtual void convert(ub::converter_t& converter) override;
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags)
  {
    return protocol_step(*this, in, out, flags);
  }
  
  virtual mpc_crypto_share_t* create_share() const override { return new mpc_ecdsa_share_t; }
  virtual mpc_crypto_key_e get_share_type() const override { return mpc_ecdsa; }
  virtual void set_share_core(const mpc_crypto_share_t& src) override { assert(false); }
  virtual void get_share_core(mpc_crypto_share_t& dst) const { ((mpc_ecdsa_share_t&)dst).core = share; }
  void set_curve(crypto::ecc_curve_ptr curve) { this->curve = curve; }

  virtual int get_messages_count() const override { return 5; }
  virtual bool changes_share() const override { return true; }

  typedef mpc::agree_random_t::message1_t message1_t;
  typedef mpc::agree_random_t::message2_t message2_t;

  struct message3_t
  {
    mpc::agree_random_t::message3_t agree_msg3;
    mpc::ecdsa_generate_t::message1_t gen_msg1;
    crypto::ecc_curve_ptr curve;

    message3_t() : curve(nullptr) {}

    void convert(ub::converter_t& converter)
    {
      converter.convert(agree_msg3);
      converter.convert(gen_msg1);
      curve.convert(converter);
    }
  };

  typedef mpc::ecdsa_generate_t::message2_t message4_t;
  typedef mpc::ecdsa_generate_t::message3_t message5_t;

  error_t party1_step1(message1_t& out);
  error_t party2_step1(const message1_t& in, message2_t& out);
  error_t party1_step2(const message2_t& in, message3_t& out);
  error_t party2_step2(const message3_t& in, message4_t& out);
  error_t party1_step3(const message4_t& in, message5_t& out);
  error_t party2_step3(const message5_t& in, none_message_t& out);

private:
  crypto::ecc_curve_ptr curve;
  mpc::ecdsa_generate_t ctx;
  mpc::ecdsa_share_t share;
  mpc::agree_random_t agree_random;
};
static ub::convertable_t::factory_t::register_t<mpc_ecdsa_gen_t, mpc_ecdsa_gen_t::CODE_TYPE> g_register_mpc_ecdsa_gen_t;

class mpc_ecdsa_sign_t : public mpc_crypto_context_t
{
public:
  static const uint64_t CODE_TYPE = 0x05b69fb6565e4ae2;
  virtual uint64_t get_type() const { return CODE_TYPE; }
  mpc_ecdsa_sign_t() {}
  virtual void convert(ub::converter_t& converter) override;
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags) override
  {
    return protocol_step(*this, in, out, flags);
  }

  virtual mpc_crypto_share_t* create_share() const override { return new mpc_ecdsa_share_t; }
  virtual mpc_crypto_key_e get_share_type() const override { return mpc_ecdsa; }
  virtual void get_share_core(mpc_crypto_share_t& dst) const 
  { 
    ((mpc_ecdsa_share_t&)dst).core = share; 
    ((mpc_ecdsa_share_t&)dst).bip = bip; 
  }
  virtual void set_share_core(const mpc_crypto_share_t& src) override 
  { 
    share = ((const mpc_ecdsa_share_t&)src).core; 
    bip = ((const mpc_ecdsa_share_t&)src).bip; 
  }
  const crypto::ecdsa_signature_t& get_signature() const { return result; }
  void set_data_to_sign(mem_t data_to_sign) { ctx.data_to_sign = data_to_sign; }
  void set_refresh(bool refresh) { this->ctx.refresh = refresh; }

  virtual int get_messages_count() const override { return 5; }
  virtual bool changes_share() const override { return ctx.refresh; }

  struct message1_t
  {
    mpc::ecdsa_sign_t::message1_t sign_msg1;
    bool refresh;
    buf_t data_to_sign;

    void convert(ub::converter_t& converter)
    {
      converter.convert(sign_msg1);
      converter.convert(refresh);
      converter.convert(data_to_sign);
    }
  };

  typedef mpc::ecdsa_sign_t::message2_t message2_t;
  typedef mpc::ecdsa_sign_t::message3_t message3_t;
  typedef mpc::ecdsa_sign_t::message4_t message4_t;
  typedef mpc::ecdsa_sign_t::message5_t message5_t;

  error_t party1_step1(message1_t& out);
  error_t party2_step1(const message1_t& in, message2_t& out);
  error_t party1_step2(const message2_t& in, message3_t& out);
  error_t party2_step2(const message3_t& in, message4_t& out);
  error_t party1_step3(const message4_t& in, message5_t& out);
  error_t party2_step3(const message5_t& in, none_message_t& out);

private:
  mpc::ecdsa_sign_t ctx;
  mpc::ecdsa_share_t share;
  mpc_ecdsa_share_t::bip_t bip;
  crypto::ecdsa_signature_t result;
};
static ub::convertable_t::factory_t::register_t<mpc_ecdsa_sign_t, mpc_ecdsa_sign_t::CODE_TYPE> g_register_mpc_ecdsa_sign_t;
