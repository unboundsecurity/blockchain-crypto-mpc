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

#include "crypto.h"
#include "ub_convert.h"

namespace ec_backup {

struct proof_z_t
{
  bn_t ry, c;
  buf_t s;

  void convert(ub::converter_t& converter)
  {
    converter.convert(ry);
    converter.convert(c);
    converter.convert(s);
  }
};

struct backup_proofs_t
{
  std::vector<proof_z_t> proofs;
  buf_t proof_e;

  void convert(ub::converter_t& converter)
  {
    converter.convert(proofs);
    converter.convert(proof_e);
  }

};

error_t generate_backup_proofs(const crypto::rsa_key_t& pub_key, ecurve_t curve, const bn_t& x_share, backup_proofs_t& backup_proofs);
error_t verify_backup_proofs(const crypto::rsa_key_t& pub_key, const ecc_point_t& Q_share, const backup_proofs_t& backup_proofs);
error_t reconstruct_private_share(const crypto::rsa_key_t& prv_key,  const ecc_point_t& Q_share, const backup_proofs_t& backup_proofs, bn_t& x_share);

error_t generate_backup_proofs_ed25519(const crypto::rsa_key_t& pub_key, const bn_t& x_share, backup_proofs_t& backup_proofs);
error_t verify_backup_proofs_ed25519(const crypto::rsa_key_t& pub_key, const crypto::ecp_25519_t& Q_share, const backup_proofs_t& backup_proofs);
error_t reconstruct_private_share_ed25519(const crypto::rsa_key_t& prv_key,  const crypto::ecp_25519_t& Q_share, const backup_proofs_t& backup_proofs, bn_t& x_share);

struct party_backup_material_t
{
  party_backup_material_t() : eddsa(false) {}

  bool eddsa;
  ecc_point_t Q_share;
  crypto::ecp_25519_t Q_share_25519;

  backup_proofs_t backup_proofs;

  void convert(ub::converter_t& converter)
  {
    converter.convert(Q_share);
    converter.convert(backup_proofs);
  }
};

struct backup_material_t
{
  backup_material_t() : rsa_bits(2048) {}

  short rsa_bits;
  std::vector<party_backup_material_t> v;
  
  void convert(ub::converter_t& converter);

  static int get_converted_size(int parties_count, int rsa_size, ecurve_t curve);
  static int get_converted_size_ed25519(int parties_count, int rsa_size);
};

error_t verify_backup_material_ed25519(const crypto::rsa_key_t& pub_key, const crypto::ecp_25519_t& Q_full, const backup_material_t& backup_material);
error_t verify_backup_material(const crypto::rsa_key_t& pub_key, const ecc_point_t& Q_full, const backup_material_t& backup_material);
error_t reconstruct_private_key_from_shares(const crypto::rsa_key_t& prv_key, const backup_material_t& backup_material, bn_t& x);


} //namespace ec_backup