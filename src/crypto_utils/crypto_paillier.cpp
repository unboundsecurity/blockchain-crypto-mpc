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

#if (OPENSSL_VERSION_NUMBER >= 0x10100000) && !defined(OPENSSL_IS_BORINGSSL)
struct rsa_meth_st
{
char *name;
    int (*rsa_pub_enc) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
    int (*rsa_pub_dec) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_enc) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_dec) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding);
    /* Can be null */
    int (*rsa_mod_exp) (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);
};
#endif

namespace crypto {

void update_public();
void update_private();


void paillier_t::convert(ub::converter_t& converter)
{
  version_t header(converter);
  converter.convert(has_private);
  converter.convert(N);
  if (has_private)
  {
    converter.convert(p);
    converter.convert(q);
  }

  if (!converter.is_write())
  {
    if (has_private) update_private();
    else update_public();
  }
}


void paillier_t::generate(int bits, bool safe)
{
  int rv = 0;

  p = bn_t::generate_prime(bits / 2, safe);
  q = bn_t::generate_prime(bits / 2, safe);
  N = p*q;

  update_private();
  has_private = true;
}

void paillier_t::update_public()
{
  // calculate N^2
  N2 = N * N;
}

void paillier_t::update_private()
{
  update_public();
  
  // calculating phi(N) = (p-1)(q-1)
  phi_N = (p-1) * (q-1);

  inv_phi_N = bn_t::inverse_mod(phi_N, N);

  // p^2
  bn_t p_sqr = p * p;

  // q^2
  bn_t q_sqr = q * q;

  // (q^2)^-1 (p^2)
  bn_t q_sqr_inverse = crypto::bn_t::inverse_mod(q_sqr, p_sqr);

  // p^2 - p
  bn_t p_sqr_minus_p = p_sqr - p;

  // q^2 - q
  bn_t q_sqr_minus_q = q_sqr - q;


  // Private key for decryption
  dec_rsa_key.create();


  dec_rsa_key.set_paillier(N2, p_sqr, q_sqr, phi_N % p_sqr_minus_p, phi_N % q_sqr_minus_q, q_sqr_inverse);  
  // n = n^2
  // e = 3
  // d = phi(N)
  // p = p^2
  // q = q^2
  // dmp1 = phi(N) mod (p^2 - p),
  // dmq1 = phi(N) mod (q^2 - q),
  // iqmp = (q^2)^-1 (p^2)
   
  // Private key for encryption
  enc_rsa_key.create();
  enc_rsa_key.set_paillier(N2, p_sqr, q_sqr, N % p_sqr_minus_p, N % q_sqr_minus_q, q_sqr_inverse);                                                 
  // n = n^2
  // e = 3
  // d = N
  // p = p^2
  // q = q^2
  // dmp1 = N mod (p^2 - p),
  // dmq1 = N mod (q^2 - q),
  // iqmp = (q^2)^-1 (p^2)
}

void paillier_t::create_prv(const bn_t& __N, const bn_t& _p, const bn_t& _q)
{
  N = __N;
  p = _p;
  q = _q;
  has_private = true;
  update_private();
}

void paillier_t::create_pub(const bn_t& __N)
{
  N = __N;
  has_private = false;
  update_public();
}

bn_t paillier_t::add_ciphers(const bn_t& src1, const bn_t& src2) const
{
  return bn_t::mul_mod(src1, src2, N2);
}

bn_t paillier_t::sub_ciphers(const bn_t& src1, const bn_t& src2) const
{
  crypto::bn_t temp = crypto::bn_t::inverse_mod(src2, N2);
  return bn_t::mul_mod(src1, temp, N2);
}

bn_t paillier_t::mul_scalar(const bn_t& cipher, const bn_t& scalar) const
{
  return crypto::bn_t::pow_mod(cipher, scalar, N2);
}

bn_t paillier_t::add_scalar(const bn_t& cipher, const bn_t& scalar) const
{
  bn_t res; MODULO(N2) { res = cipher * (scalar*N + 1); } return res;
}

bn_t paillier_t::sub_scalar(const bn_t& cipher, const bn_t& scalar) const
{
  bn_t res;  

  MODULO(N2) 
  { 
    crypto::bn_t temp = crypto::bn_t(1) - scalar*N;
    res = cipher * temp; 
  } 

  return res;
}

bn_t paillier_t::sub_cipher_scalar(const bn_t& scalar, const bn_t& cipher) const
{
  bn_t res;  
  
  crypto::bn_t temp = crypto::bn_t::inverse_mod(cipher, N2);

  MODULO(N2) 
  { 
    res = (scalar*N + 1) * temp; 
  } 

  return res;
}


bn_t paillier_t::encrypt(const bn_t& src) const
{
  return encrypt(src, bn_t::rand(N));
}


bn_t paillier_t::fast_rsa_decrypt(const rsa_key_t& rsa, const bn_t& in) //static
{
  const RSA_METHOD* std_rsa_method = RSA_get_default_method();
  bn_t result;
  std_rsa_method->rsa_mod_exp(result, in, rsa.value(), bn_t::tls_bn_ctx());
  return result;
}

bn_t paillier_t::encrypt(const bn_t& src, const bn_t& rand) const
{
  bn_t rn;
  if (has_private)
  {
    rn = fast_rsa_decrypt(enc_rsa_key, rand);
  }
  else
  {
    MODULO (N2) rn = rand.pow(N);
  }

  MODULO(N2) rn *= src * N + 1;
  return rn;
}

bn_t paillier_t::decrypt(const bn_t& src) const
{
  bn_t c1;

  if (has_private)
  {
    c1 = fast_rsa_decrypt(dec_rsa_key, src);
  }
  else
  {
    assert(false);
  }

  bn_t m1 = (c1 - 1) / N;
  MODULO(N) m1 *= inv_phi_N;
  return m1;
}


}
