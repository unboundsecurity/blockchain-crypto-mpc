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
#include "mpc_core.h"

class mpc_generic_secret_share_t : public mpc_crypto_share_t
{
public:
  static const uint64_t CODE_TYPE = 0x8b168875f23557f1;

  mpc_generic_secret_share_t() {}
  virtual void convert(ub::converter_t& converter) override;
  virtual mpc_crypto_key_e get_type() const override { return mpc_generic_secret; }
  virtual mpc_crypto_context_t* create_refresh_oper();
  
  virtual uint64_t calc_uid() const override { return get_uid(); }

  buf_t value;
};
static ub::convertable_t::factory_t::register_t<mpc_generic_secret_share_t, mpc_generic_secret_share_t::CODE_TYPE> g_register_mpc_generic_secret_share_t;


class mpc_generic_secret_refresh_t : public mpc_crypto_context_t
{
public:
  static const uint64_t CODE_TYPE = 0xaa9d4be13a15a99c;

  virtual uint64_t get_type() const override { return CODE_TYPE; }
  virtual void convert(ub::converter_t& converter) override;
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags) override
  {
    return protocol_step(*this, in, out, flags);
  }

  virtual mpc_crypto_share_t* create_share() const override { return new mpc_generic_secret_share_t; }
  virtual void get_share_core(mpc_crypto_share_t& dst) const { ((mpc_generic_secret_share_t&)dst).value = share; }
  virtual void set_share_core(const mpc_crypto_share_t& src) override { share = ((const mpc_generic_secret_share_t&)src).value; agree_random.set_size(share.size()); }

  virtual mpc_crypto_key_e get_share_type() const  override { return mpc_generic_secret; }

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
  buf_t share;
  mpc::agree_random_t agree_random;
};
static ub::convertable_t::factory_t::register_t<mpc_generic_secret_refresh_t, mpc_generic_secret_refresh_t::CODE_TYPE> g_register_mpc_generic_secret_refresh_t;

class mpc_generic_secret_gen_t : public mpc_crypto_context_t
{
public:
  mpc_generic_secret_gen_t()  {}

  static const uint64_t CODE_TYPE = 0xac01087ba9cfc7a3;

  virtual uint64_t get_type() const override { return CODE_TYPE; }
  virtual mpc_crypto_key_e get_share_type() const override { return mpc_generic_secret; }
  virtual void convert(ub::converter_t& converter) override;
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags) override
  {
    return protocol_step(*this, in, out, flags);
  }
  virtual mpc_crypto_share_t* create_share() const override { return new mpc_generic_secret_share_t; }
  virtual void get_share_core(mpc_crypto_share_t& dst) const 
  { 
    ((mpc_generic_secret_share_t&)dst).value = share; 
    ((mpc_generic_secret_share_t&)dst).set_uid(uid); 
  }
  virtual void set_share_core(const mpc_crypto_share_t& src) override { assert(false); }
  
  void set_bits(int bits) { this->bits = bits; }

  virtual int get_messages_count() const override { return 1; }
  virtual bool changes_share() const override { return true; }

  struct message1_t
  {
    int bits;
    uint64_t uid;
    void convert(ub::converter_t& converter)
    {
      converter.convert(bits);
      converter.convert(uid);
    }
  };

  error_t party1_step1(message1_t& in);
  error_t party2_step1(const message1_t& in, none_message_t& out);

protected:
  int bits;
  uint64_t uid;
  buf_t share;
};
static ub::convertable_t::factory_t::register_t<mpc_generic_secret_gen_t, mpc_generic_secret_gen_t::CODE_TYPE> g_register_mpc_generic_secret_gen_t;


class mpc_generic_secret_import_t : public mpc_crypto_context_t
{
public:
  mpc_generic_secret_import_t()  {}

  static const uint64_t CODE_TYPE = 0x9752823d92d115ce;

  virtual uint64_t get_type() const override { return CODE_TYPE; }
  virtual mpc_crypto_key_e get_share_type() const override { return mpc_generic_secret; }
  virtual void convert(ub::converter_t& converter) override;
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags) override
  {
    return protocol_step(*this, in, out, flags);
  }
  virtual mpc_crypto_share_t* create_share() const override { return new mpc_generic_secret_share_t; }
  virtual void get_share_core(mpc_crypto_share_t& dst) const 
  { 
    ((mpc_generic_secret_share_t&)dst).value = share; 
    ((mpc_generic_secret_share_t&)dst).set_uid(uid); 
  }
  virtual void set_share_core(const mpc_crypto_share_t& src) override { assert(false); }
  
  void init(mem_t value) { share = value; }

  virtual int get_messages_count() const override { return 1; }
  virtual bool changes_share() const override { return true; }

  struct message1_t
  {
    uint64_t uid;
    buf_t share;
    void convert(ub::converter_t& converter)
    {
      converter.convert(uid);
      converter.convert(share);
    }
  };

  error_t party1_step1(message1_t& in);
  error_t party2_step1(const message1_t& in, none_message_t& out);

protected:
  uint64_t uid;
  buf_t share;
};
static ub::convertable_t::factory_t::register_t<mpc_generic_secret_import_t, mpc_generic_secret_import_t::CODE_TYPE> g_register_mpc_generic_secret_import_t;
