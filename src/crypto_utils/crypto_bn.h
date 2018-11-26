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

#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include "ub_convert.h"

namespace crypto 
{


class paillier_t;
class ecdsa_signature_t;
class eddsa_key_t;
class ecc_key_t;
class ec25519;
class ecp_t;
class ecurve_t;

class bn_t // : public ub::convertable_t
{
  friend class ecp_t;
  friend class ecurve_t;
  friend class ecc_point_t;
  friend class ecc_key_t;
  friend class paillier_t;
  friend class ecdsa_signature_t;
  friend class montgomery_t;

public:
  operator const BIGNUM* () const 
  { 
#ifdef OPENSSL_BN_PTR
    return val_ptr; 
#else
    return &val; 
#endif
  }

  operator BIGNUM* () 
  { 
#ifdef OPENSSL_BN_PTR
    return val_ptr; 
#else
    return &val; 
#endif
  }

  bn_t();
  bn_t(const BIGNUM* src);
  explicit bn_t(mem_t src);
  explicit bn_t(buf128_t src);
  explicit bn_t(buf256_t src);

  ~bn_t();
  bn_t(int src);
  bn_t(const bn_t& src);
  bn_t(bn_t&& src); //move constructor
  operator int() const;
  //static bn_t copy(const BIGNUM* value);
  //BIGNUM* copy() const;

#ifdef INTEL_X64
  int64_t get_int64() const;
  void set_int64(int64_t value);
#endif

  bn_t& operator = (int src);
  bn_t& operator = (const bn_t& src);
  bn_t& operator = (bn_t&& src);  //move assignment
  bn_t& operator = (const BIGNUM* src);
  bool operator == (const bn_t& val) const;
  bool operator != (const bn_t& val) const;
  bool operator > (const bn_t& val) const;
  bool operator < (const bn_t& val) const;
  bool operator >= (const bn_t& val) const;
  bool operator <= (const bn_t& val) const;
  bool operator == (int val) const;
  bool operator != (int val) const;
  bool operator > (int val) const;
  bool operator < (int val) const;
  bool operator >= (int val) const;
  bool operator <= (int val) const;

  bn_t& operator += (const bn_t& val);
  bn_t& operator -= (const bn_t& val);
  bn_t& operator *= (const bn_t& val);
  bn_t& operator /= (const bn_t& val);
  bn_t& operator %= (const bn_t& val);
  bn_t& operator ++ ();
  bn_t operator ++ (int dummy);
  bn_t& operator += (int val);
  bn_t& operator -= (int val);
  bn_t& operator *= (int val);
  bn_t& operator /= (int val);
  bn_t& operator %= (int val);
  bn_t& operator <<= (int val);
  bn_t& operator >>= (int val);

  static bn_t pow(const bn_t& base, const bn_t& exp);
  static bn_t div(const bn_t& num, const bn_t& denum, bn_t* rem=NULL);
  static bn_t mod(const bn_t& num, const bn_t& denum);
  static bn_t sqr(const bn_t& val);
  static bn_t abs(const bn_t& val);
  static bn_t neg(const bn_t& val);
  static bn_t rand(const bn_t& range);
  static bn_t rand(int bits, bool top_bit_set = false);

  bn_t sqr() const;
  bn_t sqrt_floor() const;
  bn_t abs() const;
  bn_t neg() const;
  bool is_odd() const;
  bool is_zero() const;
  bn_t pow(const bn_t& exp) const { return pow(*this, exp); }
  bn_t pow_mod(const bn_t& exp, const bn_t& mod) const { return pow_mod(*this, exp, mod); }
  bn_t inverse_mod(const bn_t& mod) const { return inverse_mod(*this, mod); }

  bn_t lshift(int n) const;
  bn_t rshift(int n) const;
  bool is_bit_set(int n) const;
  void set_bit(int n, bool bit);

  static bn_t add_mod(const bn_t& val1, const bn_t& val2, const bn_t& mod);
  static bn_t add_mod_quick(const bn_t& val1, const bn_t& val2, const bn_t& mod); // both val1 and val2 are non-negative and less than mod
  static bn_t sub_mod(const bn_t& val1, const bn_t& val2, const bn_t& mod);
  static bn_t mul_mod(const bn_t& val1, const bn_t& val2, const bn_t& mod);
  static bn_t pow_mod(const bn_t& base, const bn_t& exp, const bn_t& mod);
  static bn_t inverse_mod(const bn_t& src, const bn_t& mod);

  bn_t inv() const; // only valid for modulo

  static bn_t generate_prime(int bits, bool safe);
  bool prime();
  static bn_t gcd(const bn_t& val1, const bn_t& val2);
  static bn_t lcm(const bn_t& val1, const bn_t& val2);
 
  int get_bit(int n) const;
  int get_bin_size() const;
  int get_bits_count() const;
  buf_t to_bin() const;
  buf_t to_bin(int size) const;
  int to_bin(byte_ptr dst) const;
  void to_bin(byte_ptr dst, int size) const;
  static bn_t from_bin(mem_t mem);
  static bn_t from_double(double value);

  std::string to_string() const;
  std::string to_hex() const;

  int get_mpi_size() const;
  buf_t to_mpi() const;
  int to_mpi(byte_ptr dst) const;
  static bn_t from_mpi(mem_t mem);
  static bn_t from_string(const_char_ptr str);
  static bn_t from_hex(const_char_ptr str);


  static int compare(const bn_t& b1, const bn_t& b2);
  int sign() const;

  friend bn_t operator + (const bn_t& val1, const bn_t& val2);
  friend bn_t operator - (const bn_t& val1, const bn_t& val2);
  friend bn_t operator * (const bn_t& val1, const bn_t& val2);
  friend bn_t operator / (const bn_t& val1, const bn_t& val2);
  friend bn_t operator % (const bn_t& val1, const bn_t& val2);
  friend bn_t operator - (const bn_t& val);

  friend bn_t operator + (const bn_t& val1, int val2);
  friend bn_t operator - (const bn_t& val1, int val2);
  friend bn_t operator * (const bn_t& val1, int val2);
  friend bn_t operator / (const bn_t& val1, int val2);
  friend bn_t operator % (const bn_t& val1, int val2);

  friend bn_t operator << (const bn_t& val1, int val2);
  friend bn_t operator >> (const bn_t& val1, int val2);

  static void set_modulo(const bn_t& n);
  static bool check_modulo();
  static void reset_modulo();

  int small_mod(int value) const;
  void truncate(int bits);

  void convert(ub::converter_t& converter); // override

private:
#ifdef OPENSSL_BN_PTR
  BIGNUM* val_ptr;
#else
  BIGNUM val;
#endif
  static BN_CTX* tls_bn_ctx();

  static bn_t pow_mod(const bn_t& base, const bn_t& exp, const BIGNUM* mod);
};

class montgomery_t
{
public:
  montgomery_t() : handle(BN_MONT_CTX_new()) {}
  ~montgomery_t() { BN_MONT_CTX_free(handle); }
  void init(const bn_t& mod);
  bn_t to_mont(const bn_t& v) const;
  bn_t from_mont(const bn_t& v) const;
  
  bn_t mul(const bn_t& v1, const bn_t& v2) const;
  bn_t sqr(const bn_t& v) const;
  bn_t reduce(const bn_t& v) const { return mul(v, 1); }

private:
  BN_MONT_CTX* handle;
};

#define MODULO(n) for (crypto::bn_t::set_modulo(n); crypto::bn_t::check_modulo(); crypto::bn_t::reset_modulo())

bn_t operator + (const bn_t& b1, const bn_t& b2);
bn_t operator - (const bn_t& b1, const bn_t& b2);
bn_t operator * (const bn_t& b1, const bn_t& b2);
bn_t operator / (const bn_t& b1, const bn_t& b2);
bn_t operator % (const bn_t& b1, const bn_t& b2);
bn_t operator - (const bn_t& b1);

bn_t operator + (const bn_t& b1, int b2);
bn_t operator - (const bn_t& b1, int b2);
bn_t operator * (const bn_t& b1, int b2);
bn_t operator / (const bn_t& b1, int b2);
bn_t operator % (const bn_t& b1, int b2);

} // namespace crypto 