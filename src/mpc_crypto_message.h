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
#include "mpc_crypto.h"
#include "ub_convert.h"

class mpc_crypto_message_t;
class mpc_crypto_context_t;

class mpc_crypto_message_t : public ub::convertable_t
{
public:
  mpc_crypto_message_t();
  virtual ~mpc_crypto_message_t() {}
  virtual void convert(ub::converter_t& converter) override;
  void get_info(mpc_crypto_message_info_t& info) const;
  
  uint64_t get_context_type() const { return context_type; }
  uint64_t get_context_uid() const { return context_uid; }
  uint64_t get_share_uid() const { return share_uid; }

  template <class T> void set(const mpc_crypto_context_t& context, int message_type, int to, T& data)
  {
    set_message_data(context, message_type, to, ub::convert(data));
  }

  template <class T> error_t get(const mpc_crypto_context_t& context, int message_type, int from, T& data) const;

  bool is_empty() const { return buffer.empty(); }
  int get_dst_peer() const { return dst_peer; }

private:
  int message_type;
  int src_peer;
  int dst_peer;
  uint64_t context_type;
  uint64_t context_uid;
  uint64_t share_uid;
  ub::buf_t buffer;

  void set_message_data(const mpc_crypto_context_t& context, int message_type, int to, const buf_t& message_data);
};

