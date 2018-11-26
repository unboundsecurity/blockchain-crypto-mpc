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

#include "precompiled.h"
#include "mpc_crypto_message.h"
#include "mpc_crypto_context.h"

MPCCRYPTO_API void MPCCrypto_freeMessage(MPCCryptoMessage* message)
{
  delete (mpc_crypto_message_t*)message;
}

MPCCRYPTO_API int MPCCrypto_messageToBuf(MPCCryptoMessage* message, uint8_t* out, int* out_size)
{
  ub::converter_t converter(out);
  converter.convert(*(mpc_crypto_message_t*)message);
  *out_size = converter.get_size();
  return 0;
}

MPCCRYPTO_API int MPCCrypto_messageFromBuf(const uint8_t* in, int in_size, MPCCryptoMessage** out_message)
{
  mpc_crypto_message_t* message = new mpc_crypto_message_t;

  if (!ub::convert(*message, ub::mem_t(in, in_size)))
  {
    delete message;
    return ub::error(E_FORMAT);
  }

  *out_message = (MPCCryptoMessage*)message;
  return 0;
}

MPCCRYPTO_API int MPCCrypto_messageInfo(MPCCryptoMessage* message, mpc_crypto_message_info_t* info)
{
  error_t rv = 0;
  if (!message || !info) return rv = ub::error(E_BADARG);

  ((mpc_crypto_message_t*)message)->get_info(*info);

  return 0;
}

void mpc_crypto_message_t::get_info(mpc_crypto_message_info_t& info) const
{
  info.src_peer = src_peer;
  info.dst_peer = dst_peer;
  info.context_uid = context_uid;
  info.share_uid = share_uid;
}

mpc_crypto_message_t::mpc_crypto_message_t():
  src_peer(0),
  dst_peer(0),
  context_type(0),
  context_uid(0),
  share_uid(0),
  message_type(0)
{
}

void mpc_crypto_message_t::convert(ub::converter_t& converter)
{
  converter.convert(context_type);
  converter.convert(context_uid);
  converter.convert(share_uid);
  converter.convert(src_peer);
  converter.convert(dst_peer);
  converter.convert(message_type);
  converter.convert(buffer);
}


void mpc_crypto_message_t::set_message_data(const mpc_crypto_context_t& context, int message_type, int to, const buf_t& message_data)
{
  buffer = message_data;

  src_peer = context.get_peer();
  dst_peer = to;
  this->message_type = message_type;

  context_type = context.get_type();
  context_uid = context.get_uid();
  share_uid = context.get_share_uid();
}

