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
#include "mpc_crypto.h"


class mpc_crypto_context_t;

class mpc_crypto_share_t : public ub::convertable_t
{
public:
  mpc_crypto_share_t() : uid(0) {}
  virtual ~mpc_crypto_share_t() {}
  virtual void convert(ub::converter_t& converter) override;

  uint64_t get_uid() const { return uid; }
  virtual mpc_crypto_key_e get_type() const = 0;
  void get_info(mpc_crypto_share_info_t& info) const;
  void set_uid(uint64_t uid) { this->uid = uid; }

  virtual mpc_crypto_context_t* create_refresh_oper() { return nullptr; }
  virtual uint64_t calc_uid() const = 0;

protected:
  static const uint64_t CODE_TYPE = 0x43bca730c19d4e0c;
  uint64_t uid;
};
