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

namespace crypto {
  
class bip_node_t
{
public:
  static bip_node_t from_master(mem_t S);
  bip_node_t derive(bool hardened, unsigned index) const;
  
  bn_t get_private_key() const;
  ecc_point_t get_public_key() const;

  std::string serialize_pub(mem_t pub_key_oct, bool main=true) const;
  std::string serialize_pub(bool main=true) const;
  std::string serialize_prv(bool main=true) const;

  void set_c_par(buf256_t c_par) { this->c_par = c_par; }
  void set_k_par(buf256_t k_par) { this->k_par = k_par; }
  void set_level(byte_t level) { this->level = level; }
  void set_parent_fingerprint(unsigned parent_fingerprint) { this->parent_fingerprint = parent_fingerprint; }
  void set_child_number(unsigned child_number) { this->child_number = child_number; }


private:
  buf256_t k_par, c_par;
  byte_t level;
  unsigned parent_fingerprint;
  unsigned child_number;
};

class bip_node_ed25519_t
{
public:
  static bip_node_ed25519_t from_master(mem_t S);
  bip_node_ed25519_t derive(bool hardened, unsigned index) const;

  std::string serialize_pub(mem_t pub_key_oct, bool main=true) const;
  std::string serialize_pub(bool main=true) const;
  std::string serialize_prv(bool main=true) const;

  void set_c_par(buf256_t c_par) { this->c_par = c_par; }
  void set_k_par(buf256_t k_par) { this->k_par = k_par; }
  void set_level(byte_t level) { this->level = level; }
  void set_parent_fingerprint(unsigned parent_fingerprint) { this->parent_fingerprint = parent_fingerprint; }
  void set_child_number(unsigned child_number) { this->child_number = child_number; }

  bn_t get_private_key() const;
  crypto::ecp_25519_t get_public_key() const;

private:
  buf256_t k_par, c_par;
  byte_t level;
  unsigned parent_fingerprint;
  unsigned child_number;

  static buf256_t generate_secret_scalar(buf256_t src);
};


} // namespace crypto