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
#include "crypto.h"
#include "mpc_crypto_context.h"

error_t mpc_crypto_context_t::get_share(mpc_crypto_share_t*& share) const
{
  if (!is_finished()) return ub::error(E_NOT_READY);
  share = create_share();
  get_share_core(*share);
  share->set_uid(share->calc_uid());
  return 0;
}

error_t mpc_crypto_context_t::set_share(const mpc_crypto_share_t& share)
{
  if (share.get_type()!=get_share_type()) return ub::error(E_BADARG); 
  set_share_core(share);
  return 0;
}


MPCCRYPTO_API void MPCCrypto_freeContext(MPCCryptoContext* context)
{
  delete (mpc_crypto_context_t*)context;
}

MPCCRYPTO_API int MPCCrypto_contextToBuf(MPCCryptoContext* context, uint8_t* out, int* out_size)
{
  ub::converter_t converter(out);
  converter.convert(*(mpc_crypto_context_t*)context);
  *out_size = converter.get_size();
  return 0;
}

MPCCRYPTO_API int MPCCrypto_contextFromBuf(const uint8_t* in, int in_size, MPCCryptoContext** out_context)
{
  ub::convertable_t* obj =  ub::convertable_t::factory_t::create(ub::mem_t(in, in_size));
  if (!obj) return ub::error(E_FORMAT);

  mpc_crypto_context_t* context = dynamic_cast<mpc_crypto_context_t*>(obj);
  if (!context) 
  {
    delete obj;
    return ub::error(E_FORMAT);
  }

  *out_context = (MPCCryptoContext*)obj;
  return 0;
}

MPCCRYPTO_API int MPCCrypto_contextInfo(MPCCryptoContext* context, mpc_crypto_context_info_t* info)
{
  error_t rv = 0;

  if (!context || !info) return rv = ub::error(E_BADARG);

  ((mpc_crypto_context_t*)context)->get_info(*info);

  return 0;
}


MPCCRYPTO_API int MPCCrypto_getShare(MPCCryptoContext* context_ptr, MPCCryptoShare** out_share)
{
  error_t rv = 0;

  if (!context_ptr) return rv = ub::error(E_BADARG);
  mpc_crypto_context_t* context = (mpc_crypto_context_t*)context_ptr;
  mpc_crypto_share_t* share = nullptr;

  if (rv = context->get_share(share)) return rv;

  *out_share = (MPCCryptoShare*)share;
  return 0;
}

MPCCRYPTO_API int MPCCrypto_step(MPCCryptoContext* ctx, MPCCryptoMessage* in, MPCCryptoMessage** out, unsigned* out_flags)
{
  error_t rv = 0;

  mpc_crypto_context_t* context = (mpc_crypto_context_t*)ctx;
  mpc_crypto_message_t* message_in = (mpc_crypto_message_t*)in;
  mpc_crypto_message_t* message_out = new mpc_crypto_message_t();

  *out_flags = 0;
  rv = context->step(*message_in, *message_out, *out_flags);
  if (rv) 
  {
    delete message_out;
    return rv;
  }

  if (message_out->is_empty())
  {
    delete message_out;
    message_out = nullptr;
  }

  *out = (MPCCryptoMessage*)message_out;
  return 0;
}

mpc_crypto_context_t::mpc_crypto_context_t() :
  peer(0),
  uid(crypto::gen_random_int<uint64_t>()),
  share_uid(0),
  current_step(0)
{
}

void mpc_crypto_context_t::convert(ub::converter_t& converter)
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(uid);
  converter.convert(share_uid);
  converter.convert(peer);
  converter.convert(current_step);
}

void mpc_crypto_context_t::get_info(mpc_crypto_context_info_t& info) const
{
  info.peer = peer;
  info.uid = uid; 
  info.share_uid = share_uid;
}

// --------------------------------------------- refresh ---------------------------------------------

MPCCRYPTO_API int MPCCrypto_initRefreshKey(int peer, MPCCryptoShare* share_ptr, MPCCryptoContext** context)
{
  error_t rv = 0;

  if (!share_ptr) return rv = ub::error(E_BADARG);
  mpc_crypto_share_t* share = (mpc_crypto_share_t*)share_ptr;

  mpc_crypto_context_t* refresh_oper = share->create_refresh_oper();
  if (!refresh_oper) return rv = ub::error(E_BADARG);

  refresh_oper->set_peer(peer);
  refresh_oper->set_share_uid(share->get_uid());
  rv = refresh_oper->set_share(*share);

  if (rv)
  {
    delete refresh_oper;
    return rv;
  }

  *context = (MPCCryptoContext*)refresh_oper;
  return 0;
}