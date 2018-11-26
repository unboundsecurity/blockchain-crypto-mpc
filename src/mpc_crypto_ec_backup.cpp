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
#include "mpc_crypto_ec_backup.h"

// ------------------------------ mpc_ecdsa_backup_t ---------------------
error_t mpc_ec_backup_t::set_pub_backup_key(mem_t backup_key)
{
  pub_backup_key = crypto::rsa_key_t::import_pub_key_info(backup_key);
  if (!pub_backup_key.valid()) return ub::error(E_FORMAT);
  return 0;
}

void mpc_ec_backup_t::get_share_core(mpc_crypto_share_t& dst) const 
{ 
  if (is_eddsa) ((mpc_eddsa_share_t&)dst).core = eddsa_share; 
  else ((mpc_ecdsa_share_t&)dst).core = ecdsa_share; 
}

void mpc_ec_backup_t::set_share_core(const mpc_crypto_share_t& src) 
{ 
  if (is_eddsa) eddsa_share = ((const mpc_eddsa_share_t&)src).core; 
  else ecdsa_share = ((const mpc_ecdsa_share_t&)src).core; 
}

void mpc_ec_backup_t::convert(ub::converter_t& converter) 
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(is_eddsa);

  if (is_eddsa) converter.convert(eddsa_share);
  else converter.convert(ecdsa_share);

  converter.convert(pub_backup_key);
  converter.convert(backup_proofs);
  converter.convert(backup_material);
  mpc_crypto_context_t::convert(converter);
}

error_t mpc_ec_backup_t::party1_step1(message1_t& out)
{
  error_t rv = 0;
  out.n = pub_backup_key.get_n();
  out.e = pub_backup_key.get_e();

  if (is_eddsa) ec_backup::generate_backup_proofs_ed25519(pub_backup_key, eddsa_share.x, backup_proofs);
  else ec_backup::generate_backup_proofs(pub_backup_key, ecdsa_share.get_curve(), ecdsa_share.x, backup_proofs);
  out.backup_proofs = backup_proofs;

  return rv;
}

error_t mpc_ec_backup_t::party2_step1(const message1_t& in, message2_t& out)
{
  error_t rv = 0;
  if (in.e!=pub_backup_key.get_e()) return ub::error(E_BADARG);
  if (in.n!=pub_backup_key.get_n()) return ub::error(E_BADARG);
  if (is_eddsa)
  {
    ecp_25519_t Q_full = eddsa_share.Q_full;
    ecp_25519_t Q_self = crypto::ec25519::mul_to_generator(eddsa_share.x);
    ecp_25519_t Q_other = Q_full - Q_self;

    if (rv = ec_backup::verify_backup_proofs_ed25519(pub_backup_key, Q_other, in.backup_proofs)) return rv;
  }
  else
  {
    ecc_point_t Q_full = ecdsa_share.Q_full;
    ecc_point_t Q_self = Q_full.get_curve().mul_to_generator(ecdsa_share.x);
    ecc_point_t Q_other = Q_full - Q_self;

    if (rv = ec_backup::verify_backup_proofs(pub_backup_key, Q_other, in.backup_proofs)) return rv;
  }

  out.e = pub_backup_key.get_e();
  out.n = pub_backup_key.get_n();

  if (is_eddsa) ec_backup::generate_backup_proofs_ed25519(pub_backup_key, eddsa_share.x, out.backup_proofs);
  else ec_backup::generate_backup_proofs(pub_backup_key, ecdsa_share.get_curve(), ecdsa_share.x, out.backup_proofs);
  return rv;
}

error_t mpc_ec_backup_t::party1_step2(const message2_t& in, none_message_t& out)
{
  error_t rv = 0;

  if (in.e!=pub_backup_key.get_e()) return ub::error(E_BADARG);
  if (in.n!=pub_backup_key.get_n()) return ub::error(E_BADARG);

  ecp_25519_t Q_full_25519; 
  ecp_25519_t Q_self_25519;
  ecp_25519_t Q_other_25519;

  ecc_point_t Q_full; 
  ecc_point_t Q_self; 
  ecc_point_t Q_other;

  if (is_eddsa)
  {
    Q_full_25519 = eddsa_share.Q_full;
    Q_self_25519 = crypto::ec25519::mul_to_generator(eddsa_share.x);
    Q_other_25519 = Q_full_25519 - Q_self_25519;

    if (rv = ec_backup::verify_backup_proofs_ed25519(pub_backup_key, Q_other_25519, in.backup_proofs)) return rv;
  }
  else
  {
    Q_full = ecdsa_share.Q_full;
    Q_self = Q_full.get_curve().mul_to_generator(ecdsa_share.x);
    Q_other = Q_full - Q_self;

    if (rv = ec_backup::verify_backup_proofs(pub_backup_key, Q_other, in.backup_proofs)) return rv;
  }
  
  backup_material.rsa_bits = pub_backup_key.size()*8;
  backup_material.v.resize(2);

  ec_backup::party_backup_material_t& party1 = backup_material.v[0];
  ec_backup::party_backup_material_t& party2 = backup_material.v[1];
  party1.backup_proofs = backup_proofs;
  party2.backup_proofs = in.backup_proofs;

  if (is_eddsa)
  {  
    party1.eddsa = true;
    party1.Q_share_25519 = Q_self_25519;
    party2.Q_share_25519 = Q_other_25519;
  }
  else
  {
    party1.eddsa = false;

    party1.Q_share = Q_self;
    party2.Q_share = Q_other;
  }

  return rv;
}

// --------------------------------------- interface ---------------------------------

MPCCRYPTO_API int MPCCrypto_initBackupEcdsaKey(int peer, MPCCryptoShare* share_ptr, const uint8_t* pub_backup_key, int pub_backup_key_size, MPCCryptoContext** context)
{
  error_t rv = 0;
  if (!context) return rv = ub::error(E_BADARG);
  if (!share_ptr) return rv = ub::error(E_BADARG);
  if (!pub_backup_key) return rv = ub::error(E_BADARG);

  mpc_ecdsa_share_t* share = dynamic_cast<mpc_ecdsa_share_t*>((mpc_crypto_share_t*)share_ptr);
  if (!share) return rv = ub::error(E_BADARG);

  mpc_ec_backup_t* backup = new mpc_ec_backup_t();
  backup->set_is_eddsa(false);
  backup->set_peer(peer);
  if (rv = backup->set_pub_backup_key(mem_t(pub_backup_key, pub_backup_key_size)))
  {
    delete backup;
    return rv;
  }
  backup->set_share_uid(share->get_uid());
  if (rv = backup->set_share(*share)) 
  {
    delete backup;
    return rv;
  }

  *context = (MPCCryptoContext*)backup;

  return rv;
}

MPCCRYPTO_API int MPCCrypto_getResultBackupEcdsaKey(MPCCryptoContext* context, uint8_t* out, int* out_size)
{
  error_t rv = 0;

  if (!context) return rv = ub::error(E_BADARG);
  mpc_ec_backup_t* ctx = dynamic_cast<mpc_ec_backup_t*>((mpc_crypto_context_t*)context);
  if (!ctx) return rv = ub::error(E_BADARG);

  int buf_size = *out_size;
  ec_backup::backup_material_t& backup_material = ctx->get_backup_material();
  buf_t result = ub::convert(backup_material);
  *out_size = result.size();
  if (out)
  {
    if (buf_size < result.size()) return ub::error(E_TOO_SMALL);
    memmove(out, result.data(), result.size());
  }

  return 0;
}

MPCCRYPTO_API int MPCCrypto_initBackupEddsaKey(int peer, MPCCryptoShare* share_ptr, const uint8_t* pub_backup_key, int pub_backup_key_size, MPCCryptoContext** context)
{
  error_t rv = 0;
  if (!context) return rv = ub::error(E_BADARG);
  if (!share_ptr) return rv = ub::error(E_BADARG);
  if (!pub_backup_key) return rv = ub::error(E_BADARG);

  mpc_eddsa_share_t* share = dynamic_cast<mpc_eddsa_share_t*>((mpc_crypto_share_t*)share_ptr);
  if (!share) return rv = ub::error(E_BADARG);

  mpc_ec_backup_t* backup = new mpc_ec_backup_t();
  backup->set_is_eddsa(true);
  backup->set_peer(peer);
  backup->set_share_uid(share->get_uid());
  if (rv = backup->set_pub_backup_key(mem_t(pub_backup_key, pub_backup_key_size)))
  {
    delete backup;
    return rv;
  }
  if (rv = backup->set_share(*share)) 
  {
    delete backup;
    return rv;
  }

  *context = (MPCCryptoContext*)backup;

  return rv;
}

MPCCRYPTO_API int MPCCrypto_getResultBackupEddsaKey(MPCCryptoContext* context, uint8_t* out, int* out_size)
{
  error_t rv = 0;

  if (!context) return rv = ub::error(E_BADARG);
  mpc_ec_backup_t* ctx = dynamic_cast<mpc_ec_backup_t*>((mpc_crypto_context_t*)context);
  if (!ctx) return rv = ub::error(E_BADARG);

  int buf_size = *out_size;
  ec_backup::backup_material_t& backup_material = ctx->get_backup_material();
  buf_t result = ub::convert(backup_material);
  *out_size = result.size();
  if (out)
  {
    if (buf_size < result.size()) return ub::error(E_TOO_SMALL);
    memmove(out, result.data(), result.size());
  }

  return 0;
}

MPCCRYPTO_API int MPCCrypto_verifyEcdsaBackupKey(const uint8_t* pub_backup_key, int pub_backup_key_size, const uint8_t* pub_key, int pub_key_size, const uint8_t* backup, int backup_size)
{
  int rv = 0;
  if (!pub_backup_key) return rv = ub::error(E_BADARG);
  if (!pub_key) return rv = ub::error(E_BADARG);
  if (!backup) return rv = ub::error(E_BADARG);

  crypto::rsa_key_t pub_rsa_key = crypto::rsa_key_t::import_pub_key_info(mem_t(pub_backup_key, pub_backup_key_size));
  if (!pub_rsa_key.valid()) return rv = ub::error(E_FORMAT);

  crypto::ecc_key_t pub_ecc_key = crypto::ecc_key_t::import_pub_key_info(mem_t(pub_key, pub_key_size));
  if (!pub_ecc_key.valid()) return rv = ub::error(E_FORMAT);

  ec_backup::backup_material_t backup_material;
  if (!ub::convert(backup_material, mem_t(backup, backup_size))) return rv = ub::error(E_FORMAT);
  if (backup_material.v.size()!=2) return rv = ub::error(E_BADARG);
  if (backup_material.v[0].eddsa || backup_material.v[1].eddsa) return rv = ub::error(E_BADARG);

  ecc_point_t point = pub_ecc_key.get_pub_key();
  if (!point.valid()) rv = ub::error(E_BADARG);
  else rv = ec_backup::verify_backup_material(pub_rsa_key, point, backup_material);

  if (rv) return rv;
  return 0;
}

MPCCRYPTO_API int MPCCrypto_restoreEcdsaKey(const uint8_t* prv_backup_key, int prv_backup_key_size, const uint8_t* pub_key, int pub_key_size, const uint8_t* backup, int backup_size, uint8_t* out, int* out_size)
{
  int rv = 0;
  if (!prv_backup_key) return rv = ub::error(E_BADARG);
  if (!out_size) return rv = ub::error(E_BADARG);
  if (!backup) return rv = ub::error(E_BADARG);
  if (!pub_key) return rv = ub::error(E_BADARG);

  crypto::rsa_key_t prv_rsa_key = crypto::rsa_key_t::import_pkcs8_prv(mem_t(prv_backup_key, prv_backup_key_size));
  if (!prv_rsa_key.valid()) return rv = ub::error(E_FORMAT);

  crypto::ecc_key_t pub_ecc_key = crypto::ecc_key_t::import_pub_key_info(mem_t(pub_key, pub_key_size));
  if (!pub_ecc_key.valid()) return rv = ub::error(E_FORMAT);


  ec_backup::backup_material_t backup_material;
  if (!ub::convert(backup_material, mem_t(backup, backup_size))) return rv = ub::error(E_FORMAT);
  if (backup_material.v.size()!=2) return rv = ub::error(E_BADARG);
  if (backup_material.v[0].eddsa || backup_material.v[1].eddsa) return rv = ub::error(E_BADARG);

  ecc_point_t point = pub_ecc_key.get_pub_key();

  bn_t x;
  if (rv = ec_backup::reconstruct_private_key_from_shares(prv_rsa_key, backup_material, x)) return rv;

  if (rv) return rv;

  ecurve_t curve = backup_material.v[0].Q_share.get_curve();
  if (curve.mul_to_generator(x) != point) return rv = ub::error(E_CRYPTO);

  crypto::ecc_key_t ecc_key;
  ecc_key.set_prv_key(curve, x);
  buf_t out_buf = ecc_key.export_pkcs8_prv();
  int buf_size = *out_size;
  *out_size = out_buf.size();
  
  if (out)
  {
    if (buf_size < out_buf.size()) return rv = ub::error(E_TOO_SMALL);
    memmove(out, out_buf.data(), out_buf.size());
  }  

  return rv;
}

MPCCRYPTO_API int MPCCrypto_verifyEddsaBackupKey(const uint8_t* pub_backup_key, int pub_backup_key_size, const uint8_t* pub_key, const uint8_t* backup, int backup_size)
{
  int rv = 0;
  if (!pub_backup_key) return rv = ub::error(E_BADARG);
  if (!pub_key) return rv = ub::error(E_BADARG);
  if (!backup) return rv = ub::error(E_BADARG);
  crypto::rsa_key_t pub_rsa_key = crypto::rsa_key_t::import_pub_key_info(mem_t(pub_backup_key, pub_backup_key_size));
  if (!pub_rsa_key.valid()) return rv = ub::error(E_FORMAT);

  ec_backup::backup_material_t backup_material;
  if (!ub::convert(backup_material, mem_t(backup, backup_size))) return rv = ub::error(E_FORMAT);
  if (backup_material.v.size()!=2) return rv = ub::error(E_BADARG);
  if (!backup_material.v[0].eddsa || !backup_material.v[1].eddsa) return rv = ub::error(E_BADARG);

  ecp_25519_t point;
  if (!point.decode(pub_key)) return rv = ub::error(E_FORMAT);

  return rv = ec_backup::verify_backup_material_ed25519(pub_rsa_key, point, backup_material);
}

MPCCRYPTO_API int MPCCrypto_restoreEddsaKey(const uint8_t* prv_backup_key, int prv_backup_key_size, const uint8_t* pub_key, const uint8_t* backup, int backup_size, uint8_t* out)  // |out|=32
{
  int rv = 0;
  if (!prv_backup_key) return rv = ub::error(E_BADARG);
  if (!out) return rv = ub::error(E_BADARG);
  if (!backup) return rv = ub::error(E_BADARG);
  if (!pub_key) return rv = ub::error(E_BADARG);

  crypto::rsa_key_t prv_rsa_key = crypto::rsa_key_t::import_pkcs8_prv(mem_t(prv_backup_key, prv_backup_key_size));
  if (!prv_rsa_key.valid()) return rv = ub::error(E_FORMAT);

  ecp_25519_t point;
  if (!point.decode(pub_key))  return rv = ub::error(E_FORMAT);

  ec_backup::backup_material_t backup_material;
  if (!ub::convert(backup_material, mem_t(backup, backup_size))) return rv = ub::error(E_FORMAT);
  if (backup_material.v.size()!=2) return rv = ub::error(E_BADARG);
  if (!backup_material.v[0].eddsa || !backup_material.v[1].eddsa) return rv = ub::error(E_BADARG);

  bn_t x;
  if (rv = ec_backup::reconstruct_private_key_from_shares(prv_rsa_key, backup_material, x)) return rv;
  crypto::ec25519::encode_scalar(x, out);

  if (crypto::ec25519::mul_to_generator(out) != point) return rv = ub::error(E_CRYPTO);
  return rv;
}

