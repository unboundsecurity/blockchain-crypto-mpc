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
#include "mpc_crypto_eddsa.h"


class mpc_ec_backup_t : public mpc_crypto_context_t
{
public:
  static const uint64_t CODE_TYPE = 0x9deb028c703fea57;
  virtual uint64_t get_type() const { return CODE_TYPE; }
  mpc_ec_backup_t() : is_eddsa(false) {}
  virtual void convert(ub::converter_t& converter) override;
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags) override
  {
    return protocol_step(*this, in, out, flags);
  }

  virtual mpc_crypto_share_t* create_share() const override { assert(false); return nullptr; }
  virtual mpc_crypto_key_e get_share_type() const override { return is_eddsa ? mpc_eddsa : mpc_ecdsa; }
  virtual void get_share_core(mpc_crypto_share_t& dst) const override;
  virtual void set_share_core(const mpc_crypto_share_t& src) override;
  ec_backup::backup_material_t& get_backup_material() { return backup_material; }
  error_t set_pub_backup_key(mem_t pub_backup_key);
  void set_is_eddsa(bool is_eddsa) { this->is_eddsa = is_eddsa; }

  virtual int get_messages_count() const override { return 2; }
  virtual bool changes_share() const override { return false; }

  struct message1_t
  {
    bn_t n, e;
    ec_backup::backup_proofs_t backup_proofs;

    void convert(ub::converter_t& converter)
    {
      converter.convert(n);
      converter.convert(e);
      converter.convert(backup_proofs);
    }
  };

  typedef message1_t message2_t;

  error_t party1_step1(message1_t& out);
  error_t party2_step1(const message1_t& in, message2_t& out);
  error_t party1_step2(const message2_t& in, none_message_t& out);

private:
  bool is_eddsa;
  mpc::ecdsa_share_t ecdsa_share;
  mpc::eddsa_share_t eddsa_share;
  crypto::rsa_key_t pub_backup_key;
  ec_backup::backup_proofs_t backup_proofs;
  ec_backup::backup_material_t backup_material;
};
static ub::convertable_t::factory_t::register_t<mpc_ec_backup_t, mpc_ec_backup_t::CODE_TYPE> g_register_mpc_ec_backup_t;

