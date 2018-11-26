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

#include "crypto_rsa.h"

namespace crypto
{

class paillier_t : public ub::convertable_t
{
public:
  paillier_t() : has_private(false) {}
  ~paillier_t()  {}

  void generate(int bits, bool safe=false);
  void create_prv(const bn_t& N, const bn_t& p, const bn_t& q);
  void create_pub(const bn_t& N);

  bn_t encrypt(const bn_t& src) const;
  bn_t encrypt(const bn_t& src, const bn_t& rand) const;
  bn_t decrypt(const bn_t& src) const;
  bn_t add_ciphers(const bn_t& src1, const bn_t& src2) const;
  bn_t sub_ciphers(const bn_t& src1, const bn_t& src2) const;
  bn_t mul_scalar(const bn_t& cipher, const bn_t& scalar) const;
  bn_t add_scalar(const bn_t& cipher, const bn_t& scalar) const;
  bn_t sub_scalar(const bn_t& cipher, const bn_t& scalar) const;
  bn_t sub_cipher_scalar(const bn_t& scalar, const bn_t& cipher) const;
  
  virtual void convert(ub::converter_t& converter);

  bool has_private_key() const { return has_private; }
  bn_t get_N2() const { return N2; }
  bn_t get_N() const { return N; }
  bn_t get_p() const { return p; }
  bn_t get_q() const { return q; }
  bn_t get_phi_N() const { return phi_N; }
  bn_t get_inv_phi_N() const { return inv_phi_N; }

  const rsa_key_t& get_enc_rsa_key() const 
  { 
    assert(has_private);
    return enc_rsa_key; 
  }

  const rsa_key_t& get_dec_rsa_key() const 
  { 
    assert(has_private);
    return dec_rsa_key; 
  }

  bn_t fast_pow_N(bn_t src) const 
  { 
    assert(has_private);
    return fast_rsa_decrypt(enc_rsa_key, src); 
  }
  bn_t fast_pow_phi_N(bn_t src) const 
  { 
    assert(has_private);
    return fast_rsa_decrypt(dec_rsa_key, src); 
  }

  static bn_t fast_rsa_decrypt(const rsa_key_t& rsa, const bn_t& in);

private:
  bool has_private;
  bn_t N;
  bn_t N2;            // cached
  bn_t p;
  bn_t q;
  bn_t phi_N;            // cached
  bn_t inv_phi_N;        // cached
  rsa_key_t enc_rsa_key; // cached
  rsa_key_t dec_rsa_key; // cached

  void update_public();
  void update_private();
};

} //namespace crypto