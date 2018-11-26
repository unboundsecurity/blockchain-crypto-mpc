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
#include "mpc_crypto_ecdsa.h"

// --------------------------------------- mpc_ecdsa_share_t ----------------------------------------------

void mpc_ecdsa_share_t::convert(ub::converter_t& converter)
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(core);
  converter.convert(bip);

  mpc_crypto_share_t::convert(converter);
}

void mpc_ecdsa_share_t::get_bip_info(bip32_info_t& bip_info) const
{
  memset(&bip_info, 0, sizeof(bip32_info_t));
  if (bip.level) 
  {
    bip_info.level = bip.level;
    bip_info.hardened = bip.hardened ? 1 : 0;
    bip_info.child_number = bip.child_number;
    bip_info.parent_fingerprint = bip.parent_fingerprint;
  }
  bip.c_par.save(bip_info.chain_code);
}

// ----------------------------------------- refresh -----------------------------------

mpc_crypto_context_t* mpc_ecdsa_share_t::create_refresh_oper() 
{ 
  return new mpc_ecdsa_refresh_t; 
}

void mpc_ecdsa_refresh_t::convert(ub::converter_t& converter)
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(refresh);
  converter.convert(share);
  converter.convert(bip);
  mpc_crypto_context_t::convert(converter);
}

error_t mpc_ecdsa_refresh_t::party1_step1(message1_t& out)
{
  refresh.peer1_step1(share, out);
  return 0;
}

error_t mpc_ecdsa_refresh_t::party2_step1(const message1_t& in, message2_t& out)
{
  error_t rv = 0;
  if (rv = refresh.peer2_step1(share, in, out)) return rv;
  return 0;
}

error_t mpc_ecdsa_refresh_t::party1_step2(const message2_t& in, message3_t& out)
{
  error_t rv = 0;
  if (rv = refresh.peer1_step2(share, in, out)) return rv;
  return 0;
}

error_t mpc_ecdsa_refresh_t::party2_step2(const message3_t& in, none_message_t& out)
{
  error_t rv = 0;
  if (rv = refresh.peer2_step2(share, in)) return rv;
  return 0;
}

// --------------------------------------- mpc_eddsa_gen_t ----------------------------------------------

void mpc_ecdsa_gen_t::convert(ub::converter_t& converter) 
{
  converter.convert_code_type(CODE_TYPE);

  curve.convert(converter);
  converter.convert(agree_random);
  converter.convert(ctx);
  converter.convert(share);
  
  mpc_crypto_context_t::convert(converter);
}
  

error_t mpc_ecdsa_gen_t::party1_step1(message1_t& out)
{
  agree_random.peer1_step1(out);
  return 0;
}

error_t mpc_ecdsa_gen_t::party2_step1(const message1_t& in, message2_t& out)
{
  error_t rv = 0;
  if (rv = agree_random.peer2_step1(in, out)) return rv;
  return 0;
}

error_t mpc_ecdsa_gen_t::party1_step2(const message2_t& in, message3_t& out)
{
  error_t rv = 0;
  ub::buf_t session_id;
  if (rv = agree_random.peer1_step2(in, out.agree_msg3, session_id)) return rv;
  ctx.peer1_step1(false, curve, session_id, share, out.gen_msg1);
  out.curve = curve;
  return 0;
}

error_t mpc_ecdsa_gen_t::party2_step2(const message3_t& in, message4_t& out)
{
  error_t rv = 0;
  if (in.curve!=curve) return rv = ub::error(E_BADARG);
  ub::buf_t session_id;
  if (rv = agree_random.peer2_step2(in.agree_msg3, session_id)) return rv;
  if (rv = ctx.peer2_step1(false, in.curve, session_id, share, in.gen_msg1, out)) return rv;
  curve = in.curve;
  return rv;
}

error_t mpc_ecdsa_gen_t::party1_step3(const message4_t& in, message5_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer1_step2(share, in, out)) return rv;
  return rv;
}

error_t mpc_ecdsa_gen_t::party2_step3(const message5_t& in, none_message_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer2_step2(share, in)) return rv;
  return rv;
}


// --------------------------------------- mpc_ecdsa_sign_t ----------------------------------------------

void mpc_ecdsa_sign_t::convert(ub::converter_t& converter)
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(ctx);
  converter.convert(share);
  converter.convert(bip);
  converter.convert(result);
  mpc_crypto_context_t::convert(converter);
}

error_t mpc_ecdsa_sign_t::party1_step1(message1_t& out)
{
  ctx.peer1_step1(share, ctx.data_to_sign, ctx.refresh, out.sign_msg1);
  out.refresh = ctx.refresh;
  out.data_to_sign = ctx.data_to_sign;
  return 0;
}

error_t mpc_ecdsa_sign_t::party2_step1(const message1_t& in, message2_t& out)
{
  error_t rv = 0;
  if (in.data_to_sign!=ctx.data_to_sign) return rv = ub::error(E_BADARG);
  if (in.refresh!=ctx.refresh) return rv = ub::error(E_BADARG);

  if (rv = ctx.peer2_step1(share, in.data_to_sign, in.refresh, in.sign_msg1, out)) return rv;
  return rv;
}

error_t mpc_ecdsa_sign_t::party1_step2(const message2_t& in, message3_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer1_step2(share, in, out)) return rv;
  return rv;
}

error_t mpc_ecdsa_sign_t::party2_step2(const message3_t& in, message4_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer2_step2(share, in, out)) return rv;
  return rv;
}

error_t mpc_ecdsa_sign_t::party1_step3(const message4_t& in, message5_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer1_step3(share, in, out)) return rv;
  result = crypto::ecdsa_signature_t::from_bin(share.get_curve(), out.signature);
  return rv;
}

error_t mpc_ecdsa_sign_t::party2_step3(const message5_t& in, none_message_t& out)
{
  error_t rv = 0;
  if (rv = ctx.peer2_step3(share, in)) return rv;
  return rv;
}



// ------------------------------- interface ------------------------------
MPCCRYPTO_API int MPCCrypto_getEcdsaPublicEx(MPCCryptoShare* share_ptr, unsigned* curve_type, uint8_t* out, int* out_len)
{
  error_t rv = 0;
  if (!share_ptr) return rv = ub::error(E_BADARG);
  mpc_ecdsa_share_t* share = dynamic_cast<mpc_ecdsa_share_t*>((mpc_crypto_share_t*)share_ptr);
  if (!share) return rv = ub::error(E_BADARG);

  ecurve_t curve = share->core.get_curve();
  *curve_type = curve.get_openssl_code();

  crypto::ecc_key_t out_key;
  out_key.set_pub_key(share->core.Q_full);
  buf_t out_buf = out_key.export_pub_key_info();

  int out_buf_len = *out_len;
  *out_len = out_buf.size();

  if (out)
  {
    if (out_buf_len < out_buf.size()) return rv = ub::error(E_TOO_SMALL);
    memmove(out, out_buf.data(), out_buf.size());
  }

  return rv;
}

MPCCRYPTO_API int MPCCrypto_getEcdsaPublic(MPCCryptoShare* share_ptr, uint8_t* out, int* out_len) 
{
  unsigned curve_type = 0;
  return MPCCrypto_getEcdsaPublicEx(share_ptr, &curve_type, out, out_len);
}

MPCCRYPTO_API int MPCCrypto_initGenerateEcdsaKeyEx(int peer, unsigned curve_type, MPCCryptoContext** context)
{
  error_t rv = 0;

  ecurve_t curve = ecurve_t::find(curve_type);
  if (!curve) return rv = ub::error(E_BADARG);

  mpc_ecdsa_gen_t* gen = new mpc_ecdsa_gen_t();
  gen->set_peer(peer);
  gen->set_curve(curve);

  *context = (MPCCryptoContext*)gen;
  return 0;
}

MPCCRYPTO_API int MPCCrypto_initGenerateEcdsaKey(int peer, MPCCryptoContext** context)
{
  return MPCCrypto_initGenerateEcdsaKeyEx(peer, NID_secp256k1, context);
}

MPCCRYPTO_API int MPCCrypto_initEcdsaSign(int peer, MPCCryptoShare* share_ptr, const uint8_t* in, int in_size, int refresh, MPCCryptoContext** context)
{
  error_t rv = 0;

  if (!share_ptr) return rv = ub::error(E_BADARG);
  mpc_ecdsa_share_t* share = dynamic_cast<mpc_ecdsa_share_t*>((mpc_crypto_share_t*)share_ptr);
  if (!share) return rv = ub::error(E_BADARG);

  mpc_ecdsa_sign_t* sign = new mpc_ecdsa_sign_t();
  sign->set_peer(peer);
  sign->set_data_to_sign(ub::mem_t(in, in_size));
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

MPCCRYPTO_API int MPCCrypto_getResultEcdsaSign(MPCCryptoContext* context, uint8_t* signature, int* out_size) // der-encoded
{
  error_t rv = 0;

  if (!context) return rv = ub::error(E_BADARG);
  mpc_ecdsa_sign_t* ctx = dynamic_cast<mpc_ecdsa_sign_t*>((mpc_crypto_context_t*)context);
  if (!ctx) return rv = ub::error(E_BADARG);

  int buf_size = *out_size;
  buf_t der = ctx->get_signature().to_der();
  *out_size = der.size();
  if (signature)
  {
    if (buf_size < der.size()) return ub::error(E_TOO_SMALL);
    memmove(signature, der.data(), der.size());
  }

  return 0;
}

MPCCRYPTO_API int MPCCrypto_verifyEcdsa(const uint8_t* pub_key, int pub_key_size, const uint8_t* in, int in_size, const uint8_t* signature, int signature_size)
{
  error_t rv = 0;
  if (!pub_key) return rv = ub::error(E_BADARG);
  if (!signature) return rv = ub::error(E_BADARG);
  if (!in) return rv = ub::error(E_BADARG);
  crypto::ecc_key_t key = crypto::ecc_key_t::import_pub_key_info(mem_t(pub_key, pub_key_size));
  if (!key.valid()) return rv = ub::error(E_BADARG);

  crypto::ecurve_t curve = crypto::curve_k256;
  crypto::ecdsa_signature_t sig = crypto::ecdsa_signature_t::from_der(curve, mem_t(signature, signature_size));
  if (!sig.valid()) return rv = ub::error(E_BADARG);

  bool ok = key.ecdsa_verify(mem_t(in, in_size), sig);
  if (!ok) return rv = ub::error(E_CRYPTO);

  return rv;
}
