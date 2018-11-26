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
#include "mpc_crypto_eddsa.h"

// --------------------------------------- mpc_eddsa_share_t ----------------------------------------------

mpc_eddsa_share_t::mpc_eddsa_share_t()
{
}

void mpc_eddsa_share_t::convert(ub::converter_t& converter)
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(core);

  mpc_crypto_share_t::convert(converter);
}

// ----------------------------------------- refresh -----------------------------------

mpc_crypto_context_t* mpc_eddsa_share_t::create_refresh_oper() 
{ 
  return new mpc_eddsa_refresh_t; 
}

void mpc_eddsa_refresh_t::convert(ub::converter_t& converter)
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(agree_random);
  converter.convert(share);
  mpc_crypto_context_t::convert(converter);
}

error_t mpc_eddsa_refresh_t::party1_step1(message1_t& out)
{
  agree_random.peer1_step1(out);
  return 0;
}

error_t mpc_eddsa_refresh_t::party2_step1(const message1_t& in, message2_t& out)
{
  agree_random.peer2_step1(in, out);
  return 0;
}

error_t mpc_eddsa_refresh_t::party1_step2(const message2_t& in, message3_t& out)
{
  buf_t agree_buf;
  agree_random.peer1_step2(in, out, agree_buf);
  bool add = (agree_buf[64*3] & 1) == 0;
  mem_t refresh_data = mem_t(agree_buf.data(), 64*3);
  share.refresh(add, refresh_data);
  return 0;
}

error_t mpc_eddsa_refresh_t::party2_step2(const message3_t& in, none_message_t& out)
{
  buf_t agree_buf;
  agree_random.peer2_step2(in, agree_buf);
  bool add = (agree_buf[64*3] & 1) != 0;
  mem_t refresh_data = mem_t(agree_buf.data(), 64*3);
  share.refresh(add, refresh_data);
  return 0;
}

// --------------------------------------- mpc_eddsa_gen_t ----------------------------------------------

mpc_eddsa_gen_t::mpc_eddsa_gen_t() : agree_random(32)
{
}

void mpc_eddsa_gen_t::convert(ub::converter_t& converter)
{
  converter.convert_code_type(CODE_TYPE);

  converter.convert(agree_random);
  converter.convert(ctx);
  converter.convert(share);
  
  mpc_crypto_context_t::convert(converter);
}


error_t mpc_eddsa_gen_t::party1_step1(message1_t& out)
{
  error_t rv = 0;
  agree_random.peer1_step1(out);
  return rv;
}

error_t mpc_eddsa_gen_t::party2_step1(const message1_t& in, message2_t& out)
{
  error_t rv = 0;
  if (rv = agree_random.peer2_step1(in, out)) return rv;
  return rv;
}

error_t mpc_eddsa_gen_t::party1_step2(const message2_t& in, message3_t& out)
{
  error_t rv = 0;
  buf_t session_id;
  if (rv = agree_random.peer1_step2(in, out.agree_msg3, session_id)) return rv;
  if (rv = ctx.peer1_step1(session_id, share, out.gen_msg1)) return rv;
  return rv;
}

error_t mpc_eddsa_gen_t::party2_step2(const message3_t& in, message4_t& out)
{
  error_t rv = 0;
  buf_t session_id;
  if (rv = agree_random.peer2_step2(in.agree_msg3, session_id)) return rv;
  if (rv = ctx.peer2_step1(session_id, share, in.gen_msg1, out)) return rv;
  return rv;
}

error_t mpc_eddsa_gen_t::party1_step3(const message4_t& in, message5_t& out)
{
  return ctx.peer1_step2(share, in, out);
}

error_t mpc_eddsa_gen_t::party2_step3(const message5_t& in, message6_t& out)
{
  return ctx.peer2_step2(share, in, out);
}

error_t mpc_eddsa_gen_t::party1_step4(const message6_t& in, none_message_t& out)
{
  return ctx.peer1_step3(share, in);
}

// --------------------------------------- mpc_eddsa_sign_t ----------------------------------------------

mpc_eddsa_sign_t::mpc_eddsa_sign_t() : refresh(false)
{
}

void mpc_eddsa_sign_t::convert(ub::converter_t& converter)
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(refresh);
  converter.convert(ctx);
  converter.convert(share);
  converter.convert(result);

  mpc_crypto_context_t::convert(converter);
}

error_t mpc_eddsa_sign_t::party1_step1(message1_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer1_step1(ctx.data_to_sign, true, share, out.sign_msg1)) return rv;
  out.refresh = refresh;
  out.data_to_sign = ctx.data_to_sign;
  return rv;
}

error_t mpc_eddsa_sign_t::party2_step1(const message1_t& in, message2_t& out)
{
  error_t rv = 0;
  if (in.data_to_sign!=ctx.data_to_sign) return rv = ub::error(E_BADARG);
  if (in.refresh!=refresh) return rv = ub::error(E_BADARG);

  if (rv = ctx.peer2_step1(in.data_to_sign, true, share, in.sign_msg1, out)) return rv;
  refresh = in.refresh;
  return rv;
}

error_t mpc_eddsa_sign_t::party1_step2(const message2_t& in, message3_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer1_step2(share, in, out)) return rv;
  return rv;
}

error_t mpc_eddsa_sign_t::party2_step2(const message3_t& in, message4_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer2_step2(share, in, out)) return rv;
  return rv;
}

error_t mpc_eddsa_sign_t::party1_step3(const message4_t& in, message5_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer1_step3(share, in, out)) return rv;
  return rv;
}

static buf_t calc_mgf(mem_t seed, int size)
{
  buf_t out(size);
  byte_ptr out_ptr = out.data();
  
  int n = 0;
  while (size>0)
  {
    sha256_t sha256; sha256.update(seed).update(n++);

    if (size < 32) 
    {
      byte_t hash[32];
      sha256.final(hash);
      memmove(out_ptr, hash, size);
      break;
    }

    sha256.final(out_ptr);
    out_ptr += 32;
    size -= 32;
  }

  return out;
}


error_t mpc_eddsa_sign_t::party2_step3(const message5_t& in, message6_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer2_step3(share, in, out)) return rv;

  if (refresh)
  {
    buf_t agree_buf = calc_mgf(ctx.session_id, 64*3+1);
    mem_t refresh_data = mem_t(agree_buf.data(), 64*3);
    bool add = (agree_buf[64*3] & 1) == 0;

    share.refresh(add, refresh_data);
  }
  return rv;
}

error_t mpc_eddsa_sign_t::party1_step4(const message6_t& in, none_message_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer1_step4(share, in, result)) return rv;

  if (refresh)
  {
    buf_t agree_buf = calc_mgf(ctx.session_id, 64*3+1);
    mem_t refresh_data = mem_t(agree_buf.data(), 64*3);
    bool add = (agree_buf[64*3] & 1) != 0;

    share.refresh(add, refresh_data);
  }
  return rv;
}

// --------------------------- interface -------------------------------------------

MPCCRYPTO_API int MPCCrypto_getEddsaPublic(MPCCryptoShare* share_ptr, uint8_t* pub_key)
{
  error_t rv = 0;

  if (!share_ptr) return rv = ub::error(E_BADARG);
  mpc_eddsa_share_t* share = dynamic_cast<mpc_eddsa_share_t*>((mpc_crypto_share_t*)share_ptr);
  if (!share) return rv = ub::error(E_BADARG);

  share->copy_pub_key(pub_key);
  return 0;
}

MPCCRYPTO_API int MPCCrypto_initGenerateEddsaKey(int peer, MPCCryptoContext** context)
{
  error_t rv = 0;

  mpc_eddsa_gen_t* gen = new mpc_eddsa_gen_t();
  gen->set_peer(peer);

  *context = (MPCCryptoContext*)gen;
  return 0;
}

MPCCRYPTO_API int MPCCrypto_initEddsaSign(int peer, MPCCryptoShare* share_ptr, const uint8_t* in, int in_size, int refresh, MPCCryptoContext** context)
{
  error_t rv = 0;

  if (!share_ptr) return rv = ub::error(E_BADARG);
  mpc_eddsa_share_t* share = dynamic_cast<mpc_eddsa_share_t*>((mpc_crypto_share_t*)share_ptr);
  if (!share) return rv = ub::error(E_BADARG);

  mpc_eddsa_sign_t* sign = new mpc_eddsa_sign_t();
  sign->set_peer(peer);
  sign->set_data_to_sign(mem_t(in, in_size));
  sign->set_share_uid(share->get_uid());
  sign->set_refresh(refresh!=0);
  if (rv = sign->set_share(*share)) 
  {
    delete sign;
    return rv;
  }

  *context = (MPCCryptoContext*)sign;
  return 0;
}

MPCCRYPTO_API int MPCCrypto_getResultEddsaSign(MPCCryptoContext* context, uint8_t* out) // 64 bytes length
{
  error_t rv = 0;

  if (!context) return rv = ub::error(E_BADARG);
  mpc_eddsa_sign_t* ctx = dynamic_cast<mpc_eddsa_sign_t*>((mpc_crypto_context_t*)context);
  if (!ctx) return rv = ub::error(E_BADARG);

  ctx->copy_result(out);
  return 0;
}

MPCCRYPTO_API int MPCCrypto_verifyEddsa(const uint8_t* pub_key, const uint8_t* in, int in_size, const uint8_t* signature) // |pub_key|=32, |signature|=64
{
  error_t rv = 0;

  crypto::eddsa_key_t key;
  key.set_pub_key(pub_key);
  bool ok = key.verify(mem_t(in, in_size), mem_t(signature, 64));
  if (!ok) return rv = ub::error(E_CRYPTO);

  return 0;
}
