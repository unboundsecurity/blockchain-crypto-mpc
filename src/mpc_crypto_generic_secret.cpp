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
#include "mpc_crypto_generic_secret.h"


void mpc_generic_secret_share_t::convert(ub::converter_t& converter) 
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(value);
  mpc_crypto_share_t::convert(converter);
}

// ----------------------------------------- refresh -----------------------------------

mpc_crypto_context_t* mpc_generic_secret_share_t::create_refresh_oper() 
{ 
  return new mpc_generic_secret_refresh_t; 
}

void mpc_generic_secret_refresh_t::convert(ub::converter_t& converter)
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(agree_random);
  converter.convert(share);
  mpc_crypto_context_t::convert(converter);
}

error_t mpc_generic_secret_refresh_t::party1_step1(message1_t& out)
{
  agree_random.peer1_step1(out);
  return 0;
}

error_t mpc_generic_secret_refresh_t::party2_step1(const message1_t& in, message2_t& out)
{
  return agree_random.peer2_step1(in, out);
}

error_t mpc_generic_secret_refresh_t::party1_step2(const message2_t& in, message3_t& out)
{
  buf_t diff;
  error_t rv = agree_random.peer1_step2(in, out, diff);
  if (rv) return rv;
  share ^= diff;
  return 0;
}

error_t mpc_generic_secret_refresh_t::party2_step2(const message3_t& in, none_message_t& out)
{
  buf_t diff;
  error_t rv = agree_random.peer2_step2(in, diff);
  if (rv) return rv;
  share ^= diff;
  return 0;
}


// --------------------------------------- gen ----------------------------------------------

void mpc_generic_secret_gen_t::convert(ub::converter_t& converter) 
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(bits);
  converter.convert(uid);
  converter.convert(share);  
  mpc_crypto_context_t::convert(converter);
}

error_t mpc_generic_secret_gen_t::party1_step1(message1_t& out)
{
  out.bits = bits;
  out.uid = uid = crypto::gen_random_int<uint64_t>();
  share = crypto::gen_random(bits/8);
  return 0;
}

error_t mpc_generic_secret_gen_t::party2_step1(const message1_t& in, none_message_t& out)
{
  error_t rv = 0;
  if (in.bits!=bits) return rv = ub::error(E_BADARG);
  uid = in.uid;
  share = crypto::gen_random(bits/8);
  return rv;
}


// --------------------------------------- import ----------------------------------------------

void mpc_generic_secret_import_t::convert(ub::converter_t& converter) 
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(uid);
  converter.convert(share);  
  mpc_crypto_context_t::convert(converter);
}

error_t mpc_generic_secret_import_t::party1_step1(message1_t& out)
{
  out.uid = uid = crypto::gen_random_int<uint64_t>();
  out.share = crypto::gen_random(share.size());
  share ^= out.share;
  return 0;
}

error_t mpc_generic_secret_import_t::party2_step1(const message1_t& in, none_message_t& out)
{
  uid = in.uid;
  share = in.share;
  return 0;
}

// ------------------------------------ interface -----------------------------

MPCCRYPTO_API int MPCCrypto_initGenerateGenericSecret(int peer, int bits, MPCCryptoContext** context)
{
  error_t rv = 0;

  if ((bits<=0) || (bits % 8)) return ub::error(E_BADARG);
  mpc_generic_secret_gen_t* gen = new mpc_generic_secret_gen_t();
  gen->set_bits(bits);
  gen->set_peer(peer);

  *context = (MPCCryptoContext*)gen;

  return rv;
}

MPCCRYPTO_API int MPCCrypto_initImportGenericSecret(int peer, const uint8_t* key, int size, MPCCryptoContext** context)
{
  error_t rv = 0;

  if ((size<=0) || !key) return ub::error(E_BADARG);
  mpc_generic_secret_import_t* ctx = new mpc_generic_secret_import_t();
  ctx->init(mem_t(key, size));
  ctx->set_peer(peer);

  *context = (MPCCryptoContext*)ctx;

  return rv;
}
