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

#include "crypto_bn.h"

namespace crypto 
{

void set_unbound_rsa(RSA* rsa);
void set_old_dyadic_rsa(RSA* rsa);

class rsa_key_t : public ub::convertable_t
{
public:
  rsa_key_t() : ptr(NULL) {}
  ~rsa_key_t() { free(); }

  rsa_key_t(const rsa_key_t& src);
  rsa_key_t(rsa_key_t&& src); //move assignment
  rsa_key_t& operator = (const rsa_key_t& src);
  rsa_key_t& operator = (rsa_key_t&& src);  //move assignment

  static rsa_key_t copy(RSA* ptr);
  RSA* copy() const;
  bool valid() const { return ptr!=nullptr; }

  void free();

  int size() const;
  RSA* value() const { return ptr; }
  void attach(RSA* value) { free(); ptr = value; }
  RSA* detach() { RSA* value=ptr; ptr=nullptr; return value; }

  void create();
  void generate(int bits, int e=65537);
  void generate(int bits, const bn_t& e);

  buf_t export_pkcs8_prv() const;
  buf_t export_pub_key_info() const;
  static rsa_key_t import_pkcs8_prv(mem_t in);
  static rsa_key_t import_pub_key_info(mem_t in);

  bool encrypt_raw(const_byte_ptr in, byte_ptr out) const;
  bool decrypt_raw(const_byte_ptr in, byte_ptr out) const;

  bool sign_pkcs1(mem_t data, hash_e hash_alg, byte_ptr signature) const;
  buf_t sign_pkcs1(mem_t data, hash_e hash_alg) const;
  bool verify_pkcs1(mem_t data, hash_e hash_alg, const_byte_ptr signature) const;

  static bool pad_for_sign_pkcs1(int bits, mem_t data, hash_e hash_alg, byte_ptr out);
  static buf_t pad_for_sign_pkcs1(int bits, mem_t data, hash_e hash_alg);
  static bool unpad_and_verify_pkcs1(mem_t data, hash_e hash_alg, mem_t test);

  bool encrypt_pkcs1(mem_t in, byte_ptr out) const;
  buf_t encrypt_pkcs1(mem_t in) const;
  int decrypt_pkcs1(mem_t in, byte_ptr out) const;
  bool decrypt_pkcs1(mem_t in, buf_t& out) const;

  static bool pad_for_encrypt_pkcs1(int bits, mem_t in, byte_ptr out);
  static buf_t pad_for_encrypt_pkcs1(int bits, mem_t in);
  static int unpad_decrypted_pkcs1(mem_t in, byte_ptr out);
  static bool unpad_decrypted_pkcs1(mem_t in, buf_t& out);

  bool sign_pss(mem_t data, hash_e hash_alg, hash_e mgf_alg, int salt_size, byte_ptr signature) const;
  buf_t sign_pss(mem_t data, hash_e hash_alg, hash_e mgf_alg, int salt_size) const;
  bool verify_pss(mem_t data, hash_e hash_alg, hash_e mgf_alg, int salt_size, const_byte_ptr signature) const;

  bool encrypt_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, byte_ptr out) const;
  buf_t encrypt_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label) const;
  int decrypt_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, byte_ptr out) const;
  bool decrypt_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, buf_t& out) const;

  static bool pad_pss(int bits, mem_t data, hash_e hash_alg, hash_e mgf_alg, int salt_size, const_byte_ptr salt, byte_ptr out);
  static buf_t pad_pss(int bits, mem_t data, hash_e hash_alg, hash_e mgf_alg, int salt_size, const_byte_ptr salt = nullptr);
  static bool unpad_pss(mem_t in, hash_e hash_alg, hash_e mgf_alg, int salt_size, mem_t test);

  static bool pad_oaep(int bits, mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, byte_ptr out);
  static buf_t pad_oaep(int bits, mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label);
  static int unpad_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, byte_ptr out);
  static bool unpad_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, buf_t& out);

  virtual void convert(ub::converter_t& converter);
  
  struct data_t { BIGNUM *n, *e, *d, *p, *q, *dp, *dq, *qinv; };
  static data_t get(const RSA* ptr);
  data_t get() const { return get(ptr); }

  bn_t get_e() const { return bn_t(get().e); }
  bn_t get_n() const { return bn_t(get().n); }
  bn_t get_d() const { return bn_t(get().d); }
  bn_t get_p() const { return bn_t(get().p); }
  bn_t get_q() const { return bn_t(get().q); }
  bn_t get_dp() const { return bn_t(get().dp); }
  bn_t get_dq() const { return bn_t(get().dq); }
  bn_t get_qinv() const { return bn_t(get().qinv); }

  static void set(RSA* rsa, const BIGNUM *n, const BIGNUM *e);
  static void set(RSA* rsa, const BIGNUM *n, const BIGNUM *e, const BIGNUM *d);
  static void set(RSA* rsa, const BIGNUM *n, const BIGNUM *e, const BIGNUM *d, const BIGNUM *p, const BIGNUM *q, const BIGNUM *dp, const BIGNUM *dq, const BIGNUM *qinv);
  
  void set(const BIGNUM *n, const BIGNUM *e)
  {
    set(ptr, n, e);
  }
  void set(const BIGNUM *n, const BIGNUM *e, const BIGNUM *d)
  {
    set(ptr, n, e, d);
  }
  void set(const BIGNUM *n, const BIGNUM *e, const BIGNUM *d, const BIGNUM *p, const BIGNUM *q, const BIGNUM *dp, const BIGNUM *dq, const BIGNUM *qinv)
  {
    return set(ptr, n, e, d, p, q, dp, dq, qinv);
  }
  static void set(RSA* rsa, const data_t& data);
  void set(const data_t& data)
  {
    return set(ptr, data);
  }

  void set_paillier(const BIGNUM *n, const BIGNUM *p, const BIGNUM *q, const BIGNUM *dp, const BIGNUM *dq, const BIGNUM *qinv);

  bool has_prv() const;


  static int RSA_padding_add_PKCS1_PSS_ex(int rsa_size, unsigned char *EM,
    const unsigned char *mHash, int mHashLen,
    const EVP_MD *Hash, const EVP_MD *mgf1Hash, int sLen, const unsigned char* salt_data = nullptr);

  static int RSA_verify_PKCS1_PSS_ex(int rsa_size, const unsigned char *mHash, int mHashLen,
    const EVP_MD *Hash, const EVP_MD *mgf1Hash,
    const unsigned char *EM, int sLen);

  static int RSA_padding_add_PKCS1_OAEP_ex(unsigned char *to, int tlen,
    const unsigned char *from, int flen,
    const unsigned char *param, int plen,
    const EVP_MD *md, const EVP_MD *mgf1md);

  static int RSA_padding_add_PKCS1_OAEP_ex(unsigned char *to, int tlen,
    const unsigned char *from, int flen,
    const unsigned char *param, int plen,
    const EVP_MD *md, const EVP_MD *mgf1md,
    const unsigned char *seed, int seedlen);

  static int RSA_padding_check_PKCS1_OAEP_ex(unsigned char *to, int tlen,
    const unsigned char *from, int flen,
    int num, const unsigned char *param,
    int plen, const EVP_MD *md,
    const EVP_MD *mgf1md);

  RSA* ptr;
};

} //namespace crypto 
