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
#include "ec25519_core.h"

#ifndef NID_ED25519
#define NID_ED25519 1087
#endif

namespace crypto
{
void set_unbound_ecc(EC_KEY* ecc);
void set_old_dyadic_ecc(EC_KEY* ecc);

struct ecurve_data_t;
class ecc_generator_point_t;
class ecc_point_t;

enum
{
  MAX_EC_OID_SIZE = 16,
  MAX_EC_SIZE = 66,
  MAX_ECPOINT_COMPRESSED_OCT_SIZE = 1 + MAX_EC_SIZE,
  MAX_ECPOINT_OCT_SIZE = 1 + MAX_EC_SIZE * 2,
  MAX_ECPOINT_DER_SIZE = 3 + MAX_ECPOINT_OCT_SIZE,
};


class ecurve_t
{
public:
  ecurve_t(const ecurve_data_t* _ptr = nullptr) : ptr(_ptr) {}
  bool operator == (const ecurve_t& src) const { return ptr==src.ptr; }
  bool operator != (const ecurve_t& src) const { return ptr!=src.ptr; }
  bool operator ! () const { return ptr==nullptr; }

  bool operator == (null_ptr_t) const { return ptr==nullptr; }
  bool operator != (null_ptr_t) const { return ptr!=nullptr; }
  operator bool() const { return ptr!=nullptr; }

  mem_t oid() const;
  int get_openssl_code() const;
  int get_dyadic_code() const;
  int get_kmip_code() const;
  int bits() const;
  const_char_ptr get_name() const;

  unsigned get_magic_ecdsa_pub() const;
  unsigned get_magic_ecdsa_prv() const;
  unsigned get_magic_ecdh_pub() const;

  static ecurve_t find(const mem_t oid);
  static ecurve_t find(const_char_ptr name);
  static ecurve_t find(int openssl_id);
  static ecurve_t find_dyadic(int dyadic_code);
  static ecurve_t find_kmip(int kmip_code);
  static ecurve_t find(const EC_GROUP* group);

  int size() const;
  
  int get_der_point_size() const;
  int get_oct_point_size() const { return 1+size()*2; }
  int get_compressed_oct_point_size() const { return 1+size(); }

  const_byte_ptr der_to_octet_string(mem_t der) const;
  int octet_string_to_der(const_byte_ptr octet_string, byte_ptr out) const;
  buf_t octet_string_to_der(const_byte_ptr octet_string) const;

  int point_to_der(const EC_POINT* point, byte_ptr out) const;
  buf_t point_to_der(const EC_POINT* point) const;

  int point_to_oct(const EC_POINT* point, byte_ptr out) const;
  buf_t point_to_oct(const EC_POINT* point) const;

  int point_to_compressed_oct(const EC_POINT* point, byte_ptr out) const;
  buf_t point_to_compressed_oct(const EC_POINT* point) const;

  ecc_point_t oct_to_point(mem_t in) const;
  ecc_point_t der_to_point(mem_t in) const;
  const ecc_generator_point_t& generator() const;
  ecc_point_t mul_to_generator(const bn_t& val) const;

  const bn_t& order() const;

  void get_params(bn_t& p, bn_t& a, bn_t& b) const;

#ifdef _WIN32
  const_byte_ptr win32_der_to_point(mem_t der) const;
  int win32_point_to_der(const_byte_ptr point, byte_ptr out) const;
  buf_t win32_point_to_der(const_byte_ptr point) const;
#endif

  bn_t get_random_value() const;
  bool check(const ecc_point_t& point) const;

  const EC_GROUP* get_group() const;

  void convert(ub::converter_t& converter);

private:
  const ecurve_data_t* ptr;
  int out_der_header(byte_ptr out) const;
};

typedef ecurve_t ecc_curve_ptr;


extern ecurve_t curve_p256;
extern ecurve_t curve_p384;
extern ecurve_t curve_p521;
extern ecurve_t curve_k256;
extern ecurve_t curve_p192;
extern ecurve_t curve_p224;
extern ecurve_t curve_k224;

class ecc_point_t 
{
  friend class ecc_key_t;
  friend class certificate_t;

public:
  operator const EC_POINT* () const { return ptr; }
  operator EC_POINT* () { return ptr; }

  ecc_point_t() : curve(nullptr), ptr(nullptr) {}
  ecc_point_t(ecurve_t curve);
  ecc_point_t(ecurve_t curve, const EC_POINT* ptr);
  ecc_point_t(ecurve_t curve, const bn_t& x, const bn_t& y);

  ecc_point_t& operator = (const ecc_point_t& src);
  ecc_point_t& operator = (ecc_point_t&& src);  //move assignment

  ~ecc_point_t() { free(); }
  bool valid() const { return ptr!=nullptr; }
  void free();

  void get_projective_coordinates(bn_t& x, bn_t& y, bn_t& z);

  ecc_point_t(const ecc_point_t& src);
  ecc_point_t(ecc_point_t&& src); //move constructor
  ecurve_t get_curve() const { return curve; }

  int to_oct(byte_ptr out) const;
  
  buf_t to_oct() const 
  { 
    buf_t out(to_oct(nullptr)); 
    to_oct(out.data()); 
    return out; 
  }

  int to_compressed_oct(byte_ptr out) const;
  buf_t to_compressed_oct() const 
  { 
    buf_t out(to_compressed_oct(nullptr)); 
    to_compressed_oct(out.data()); 
    return out; 
  }

  static ecc_point_t from_oct(ecurve_t curve, mem_t in);
  buf_t to_bin() const { return to_compressed_oct(); }

  int to_der(byte_ptr out) const;
  buf_t to_der() const 
  { 
    buf_t out(to_der(nullptr)); 
    to_der(out.data()); 
    return out; 
  }

  static ecc_point_t from_der(ecurve_t curve, mem_t in);

  void get_projective_coordinates(bn_t& x, bn_t& y, bn_t& z) const;

  void get_coordinates(bn_t& x, bn_t& y) const;
  void get_x(bn_t& x) const;
  void get_y(bn_t& y) const;

  bn_t get_x() const;
  bn_t get_y() const;

  void set_coordinates(const bn_t& x, const bn_t& y);
  bool is_on_curve() const;
  bool is_infinity() const;
  void invert();
  void set_infinity();

  ecc_point_t& operator += (const ecc_point_t& val);
  ecc_point_t& operator -= (const ecc_point_t& val);
  ecc_point_t& operator *= (const bn_t& val);
  bool operator == (const ecc_point_t& val) const;
  bool operator != (const ecc_point_t& val) const;

  friend ecc_point_t operator + (const ecc_point_t& val1, const ecc_point_t& val2);
  friend ecc_point_t operator - (const ecc_point_t& val1, const ecc_point_t& val2);
  friend ecc_point_t operator * (const ecc_point_t& val1, const bn_t& val2);

  static ecc_point_t mul(const bn_t& n, const ecc_point_t& q, const bn_t& m);
  static ecc_point_t mul(const bn_t& n, const std::vector<ecc_point_t>& q, const std::vector<bn_t>& m);
  static ecc_point_t mul(const std::vector<ecc_point_t>& q, const std::vector<bn_t>& m);

  static ecc_point_t add(const ecc_point_t& val1, const ecc_point_t& val2);
  static ecc_point_t sub(const ecc_point_t& val1, const ecc_point_t& val2);
  static ecc_point_t mul(const ecc_point_t& val1, const bn_t& val2);

  bool set_compressed_coordinates(const bn_t& x, int y_bits);

  void attach(ecurve_t curve, EC_POINT* value);
  EC_POINT* detach() { EC_POINT* value=ptr; ptr=nullptr; return value; }

  void convert(ub::converter_t& converter); // override

protected:
  ecurve_t curve;
  EC_POINT* ptr;
};

ecc_point_t operator + (const ecc_point_t& val1, const ecc_point_t& val2);
ecc_point_t operator - (const ecc_point_t& val1, const ecc_point_t& val2);
ecc_point_t operator * (const ecc_point_t& val1, const bn_t& val2);

class ecc_generator_point_t : public ecc_point_t
{
  friend struct ecurve_data_t;
  friend ecc_point_t operator * (const ecc_generator_point_t& val1, const bn_t& val2);

public:
  ecc_generator_point_t() {}
  ecc_generator_point_t(const ecc_point_t& point) : ecc_point_t(point) {}
};

ecc_point_t operator * (const ecc_generator_point_t& val1, const bn_t& val2);

class ecdsa_signature_t
{
  friend class ecc_key_t;

public:
  ecdsa_signature_t() : curve(nullptr) {}
  ecdsa_signature_t(ecurve_t src_curve, const bn_t& src_r, const bn_t& src_s) : curve(src_curve), r(src_r), s(src_s) {}
  
  static ecdsa_signature_t from_bin(ecurve_t curve, mem_t mem);
  static ecdsa_signature_t from_der(ecurve_t curve, mem_t mem);

  buf_t to_bin() const;
  buf_t to_der() const;

  int to_bin(byte_ptr out) const;
  int to_der(byte_ptr out) const;

  bn_t get_r() const { return r; };
  bn_t get_s() const { return s; };
  ecurve_t get_curve() const { return curve; };

  bool valid() const { return r!=0; }

  void convert(ub::converter_t& converter);

  int get_recovery_code(mem_t in, const ecc_point_t& pub_key);
  ecc_point_t recover_pub_key(mem_t in, int recovery_code);

private:
  ecurve_t curve;
  bn_t r, s;
};

class ecc_key_t 
{
public:
  ecc_key_t() : ptr(NULL), curve(NULL) {}
  ~ecc_key_t() { free(); } 
  
  ecc_key_t(const ecc_key_t& src);
  ecc_key_t(ecc_key_t&& src); // move
  ecc_key_t& operator = (const ecc_key_t& src);
  ecc_key_t& operator = (ecc_key_t&& src);  //move assignment
  
  int size() const { return curve.size(); }
  void generate(ecurve_t _curve);

  buf_t get_pub_key_der() const { return get_pub_key().to_der(); }; // der
  ecc_point_t get_pub_key() const;
  bn_t get_prv_key() const;
  buf_t get_prv_key_buf() const;

  void set_prv_key(ecurve_t curve, const bn_t& prv_key); 
  void set_pub_key_der(ecurve_t curve, mem_t pub_key); // der 
  void set_pub_key(const ecc_point_t& pub_key); 
  void ecdh(const ecc_point_t& pub_key, byte_ptr out) const; 
  buf_t ecdh(const ecc_point_t& pub_key) const; 
  
  ecdsa_signature_t ecdsa_sign(mem_t in);
  bool ecdsa_verify(mem_t in, const ecdsa_signature_t& signature);


  bool valid() const { return ptr!=nullptr; }
  
  void free();
  EC_KEY* value() const { return ptr; }


  void attach(EC_KEY* value);
  EC_KEY* detach() { EC_KEY* value=ptr; ptr=nullptr; return value; }

  ecurve_t get_curve() const { return curve; };


  buf_t export_pub_key_info() const;
  buf_t export_pkcs8_prv() const;
  static ecc_key_t import_pkcs8_prv(mem_t in);
  static ecc_key_t import_pub_key_info(mem_t in);

private:
  EC_KEY* ptr;
  ecurve_t curve;

  bool from_evp_key(EVP_PKEY *key);
};

class ecp_25519_t;
class ecp_gen_25519_t;

class ec25519
{
public:

  static buf_t encode_scalar(const bn_t& val);
  static int encode_scalar(const bn_t& val, byte_ptr out);
  static bn_t decode_scalar(const_byte_ptr scalar);
  static bn_t decode_scalar(mem_t scalar);

  static buf_t reduce_scalar_64(const_byte_ptr scalar64);
  static buf_t reduce_scalar_64(mem_t scalar64);
  static void reduce_scalar_64(const_byte_ptr scalar64, byte_ptr out);
  static void reduce_scalar_64(mem_t scalar64, byte_ptr out);

  static bool check(const ecp_25519_t& Q);

  static ecp_25519_t mul_to_generator(const_byte_ptr scalar);
  static ecp_25519_t mul_to_generator(mem_t scalar);
  static ecp_25519_t mul_to_generator(const bn_t& scalar);

  static void scalar_muladd(byte_ptr dst, const_byte_ptr a, const_byte_ptr b, const_byte_ptr c); //(ab+c) mod l
  static buf_t scalar_muladd(mem_t a, mem_t b, mem_t c); //(ab+c) mod l

  static const ecp_gen_25519_t& generator();
  static bn_t order();
  static bn_t rand() { return bn_t::rand(order()); }

};

class ecp_25519_t
{
  friend class ec25519;

public:
  ecp_25519_t() { memset(&ge_p3, 0, sizeof(ge_p3)); }
  void convert(ub::converter_t& converter);

  buf_t encode() const;
  int encode(byte_ptr out) const;
      
  bool decode(const_byte_ptr in);
  bool decode(mem_t in);

  void invert();

  bool operator == (const ecp_25519_t& val) const;
  bool operator != (const ecp_25519_t& val) const;

  ecp_25519_t& operator += (const ecp_25519_t& val) { return *this = *this + val; }
  ecp_25519_t& operator -= (const ecp_25519_t& val) { return *this = *this - val; }
  ecp_25519_t& operator *= (const bn_t& val)        { return *this = *this * val; }

  friend ecp_25519_t operator + (const ecp_25519_t& val1, const ecp_25519_t& val2);
  friend ecp_25519_t operator - (const ecp_25519_t& val1, const ecp_25519_t& val2);
  friend ecp_25519_t operator * (const ecp_25519_t& val1, const bn_t& val2);

  friend ecp_25519_t operator * (const ecp_gen_25519_t& G, const bn_t& val);

  buf_t to_bin() const 
  { 
    buf_t out(32); 
    encode(out.data()); 
    return out; 
  }

protected:
  ec25519_core::ge_p3 ge_p3;
};

ecp_25519_t operator + (const ecp_25519_t& val1, const ecp_25519_t& val2);
ecp_25519_t operator - (const ecp_25519_t& val1, const ecp_25519_t& val2);
ecp_25519_t operator * (const ecp_25519_t& val1, const bn_t& val2);

class ecp_gen_25519_t : public ecp_25519_t
{
  friend class ec25519;
};

ecp_25519_t operator * (const ecp_gen_25519_t& val1, const bn_t& val2);

class eddsa_key_t 
{
public:
  ~eddsa_key_t() { ub::secure_bzero(prv_key, sizeof(prv_key)); }

  void generate();

  void set_prv_key(mem_t prv_key);
  void set_prv_key(const_byte_ptr prv_key);

  bn_t get_prv_key_bn() const;
  mem_t get_prv_key() const { return mem_t(prv_key, 32); }

  void set_pub_key(const ecp_25519_t& pub_key);
  void set_pub_key(mem_t pub_key);
  void set_pub_key(const_byte_ptr pub_key);

  ecp_25519_t get_pub_key_point() const;
  mem_t get_pub_key() const { return mem_t(pub_key, 32); }

  void sign(mem_t in, byte_ptr out) const;
  buf_t sign(mem_t in) const;
  bool verify(mem_t in, const_byte_ptr signature) const;
  bool verify(mem_t in, mem_t signature) const;

  static void encode_prv_key(byte_ptr dst, const_byte_ptr src);
  static buf_t encode_prv_key(mem_t src);

  static buf_t sign(const bn_t& prv_key, mem_t data);

private:
  byte_t prv_key[32];
  byte_t pub_key[32];
};

enum
{
  ecies_gcm_iv_size = 12,
  ecies_gcm_tag_size = 12,
};

#ifdef OPENSSL_GCM_SUPPORT
buf_t ecies_encrypt(const ecc_point_t& pub_key, mem_t auth, mem_t in);
int ecies_encrypt(const ecc_point_t& pub_key, mem_t auth, mem_t in, byte_ptr out);
bool ecies_decrypt(const ecc_key_t& prv_key, mem_t in, mem_t auth, buf_t& out);
int ecies_decrypt(const ecc_key_t& prv_key, mem_t in, mem_t auth, byte_ptr out);
ecc_point_t ecies_get_pub_key(mem_t in);
bool ecies_decrypt(mem_t ecdh_secret, mem_t in, mem_t auth, buf_t& out);
int ecies_decrypt(mem_t ecdh_secret, mem_t in, mem_t auth, byte_ptr out);
#endif

//typedef ecc_point_t ecp_t;
//typedef ecc_generator_point_t ecp_gen_t;

}
// namespace crypto