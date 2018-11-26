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
#include "ub_convert.h"
#include "crypto.h"

namespace crypto {

static uint8_t p192_oid[]    = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01 };
static uint8_t p256_oid[]    = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static uint8_t p384_oid[]    = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
static uint8_t p521_oid[]    = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
static uint8_t k256_oid[]    = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a };
static uint8_t p224_oid[]    = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21 };
static uint8_t k224_oid[]    = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x20 };
static uint8_t ed25519_oid[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };
//static uint8_t x25519_oid[]  = { 0x06, 0x03, 0x2b, 0x65, 0x6e };

static EC_GROUP* get_optimized_curve(int type)
{
  EC_GROUP* group = EC_GROUP_new_by_curve_name(type);
  if (group) EC_GROUP_precompute_mult(group, NULL);
  if (!group) ERR_clear_error();
  return group;
}

struct ecurve_data_t
{

public:
  //friend class ecc_point_t;
  const_char_ptr name;
  const_byte_ptr oid_ptr;
  int oid_size;
  int bits;
  int openssl_code;
  int dyadic_code;
  int kmip_code;

#ifdef _WIN32
  LPWSTR alg_ecdh, alg_ecdsa;
  DWORD magic_ecdh_pub, magic_ecdsa_pub;
  DWORD magic_ecdh_prv, magic_ecdsa_prv;
#else
  int alg_ecdh, alg_ecdsa;
  int magic_ecdh_pub, magic_ecdsa_pub;
  int magic_ecdh_prv, magic_ecdsa_prv;
#endif

//private:
  mutable ub::once_t init_once;
  mutable const EC_GROUP* group;
  mutable bn_t* order_ptr;
  mutable ecc_generator_point_t* generator_ptr;
  void check_init_once() const;

};

#ifndef _WIN32
enum {BCRYPT_ECDH_P256_ALGORITHM=0, BCRYPT_ECDSA_P256_ALGORITHM=0, BCRYPT_ECDH_PUBLIC_P256_MAGIC=0, BCRYPT_ECDSA_PUBLIC_P256_MAGIC=0, BCRYPT_ECDH_PRIVATE_P256_MAGIC=0, BCRYPT_ECDSA_PRIVATE_P256_MAGIC=0};
enum {BCRYPT_ECDH_P384_ALGORITHM=0, BCRYPT_ECDSA_P384_ALGORITHM=0, BCRYPT_ECDH_PUBLIC_P384_MAGIC=0, BCRYPT_ECDSA_PUBLIC_P384_MAGIC=0, BCRYPT_ECDH_PRIVATE_P384_MAGIC=0, BCRYPT_ECDSA_PRIVATE_P384_MAGIC=0};
enum {BCRYPT_ECDH_P521_ALGORITHM=0, BCRYPT_ECDSA_P521_ALGORITHM=0, BCRYPT_ECDH_PUBLIC_P521_MAGIC=0, BCRYPT_ECDSA_PUBLIC_P521_MAGIC=0, BCRYPT_ECDH_PRIVATE_P521_MAGIC=0, BCRYPT_ECDSA_PRIVATE_P521_MAGIC=0};
#endif

static ecurve_data_t g_curves[] = 
{
  { "1.2.840.10045.3.1.7", p256_oid, sizeof(p256_oid), 256, NID_X9_62_prime256v1, 0, 7, 
    BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDH_PUBLIC_P256_MAGIC, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_ECDH_PRIVATE_P256_MAGIC, BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
    ub::once_init, 0, 0, 0
  },
  { "1.3.132.0.34",        p384_oid, sizeof(p384_oid), 384, NID_secp384r1, 1, 10, 
    BCRYPT_ECDH_P384_ALGORITHM, BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_ECDH_PUBLIC_P384_MAGIC, BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_ECDH_PRIVATE_P384_MAGIC, BCRYPT_ECDSA_PRIVATE_P384_MAGIC,
    ub::once_init, 0, 0, 0
  },
  { "1.3.132.0.35",        p521_oid, sizeof(p521_oid), 521, NID_secp521r1, 2, 13, 
    BCRYPT_ECDH_P521_ALGORITHM, BCRYPT_ECDSA_P521_ALGORITHM, BCRYPT_ECDH_PUBLIC_P521_MAGIC, BCRYPT_ECDSA_PUBLIC_P521_MAGIC, BCRYPT_ECDH_PRIVATE_P521_MAGIC, BCRYPT_ECDSA_PRIVATE_P521_MAGIC,
    ub::once_init, 0, 0, 0
  },
  { "1.3.132.0.10",        k256_oid, sizeof(k256_oid), 256, NID_secp256k1, 3, 25, 
    0, 0, 0, 0, 0, 0,
    ub::once_init, 0, 0, 0
  },
  { "1.2.840.10045.3.1.1", p192_oid, sizeof(p192_oid), 192, NID_X9_62_prime192v1, 4, 1, 
    0, 0, 0, 0, 0, 0,
    ub::once_init, 0, 0, 0
  },
  { "1.3.132.0.33",        p224_oid, sizeof(p224_oid), 224, NID_secp224r1, 5, 4, 
    0, 0, 0, 0, 0, 0,
    ub::once_init, 0, 0, 0
  },
  { "1.3.132.0.32",        k224_oid, sizeof(k224_oid), 224, NID_secp224k1, 6, 24, 
    0, 0, 0, 0, 0, 0,
    ub::once_init, 0, 0, 0
  },
};


ecurve_t curve_p256     = ecurve_t(g_curves+0);
ecurve_t curve_p384     = ecurve_t(g_curves+1);
ecurve_t curve_p521     = ecurve_t(g_curves+2);
ecurve_t curve_k256     = ecurve_t(g_curves+3);
ecurve_t curve_p192     = ecurve_t(g_curves+4);
ecurve_t curve_p224     = ecurve_t(g_curves+5);
ecurve_t curve_k224     = ecurve_t(g_curves+6);

ecurve_t ecurve_t::find(mem_t oid)
{
  for (int i=0; i<_countof(g_curves); i++)
  {
    ecurve_t curve = ecurve_t(g_curves+i);
    if (!curve.get_group()) continue;
    if (curve.oid()==oid) return curve;
  }
  crypto::error("Curve not found by OID");
  return nullptr;
}

ecurve_t ecurve_t::find(const_char_ptr name)
{
  for (int i=0; i<_countof(g_curves); i++)
  {
    ecurve_t curve = ecurve_t(g_curves+i);
    if (!curve.get_group()) continue;
    if (0==strcmp(curve.get_name(), name)) return curve;
  }
  crypto::error("Curve not found, name=" + std::string(name));
  return nullptr;
}

ecurve_t ecurve_t::find(int openssl_id)
{
  if (openssl_id==0) return nullptr;

  for (int i=0; i<_countof(g_curves); i++)
  {
    ecurve_t curve = ecurve_t(g_curves+i);
    if (!curve.get_group()) continue;
    if (openssl_id==curve.get_openssl_code()) return curve;
  }
  crypto::error("Curve not found, openssl-code=" + strext::itoa(openssl_id));
  return nullptr;
}

ecurve_t ecurve_t::find_dyadic(int dyadic_id)
{
  for (int i=0; i<_countof(g_curves); i++)
  {
    ecurve_t curve = g_curves+i;
    if (!curve.get_group()) continue;
    if (dyadic_id==curve.get_dyadic_code()) return curve;
  }
  crypto::error("Curve not found, ub-code=" + strext::itoa(dyadic_id));
  return nullptr;
}

ecurve_t ecurve_t::find_kmip(int kmip_id)
{
  for (int i=0; i<_countof(g_curves); i++)
  {
    ecurve_t curve = ecurve_t(g_curves+i);
    if (!curve.get_group()) continue;
    if (kmip_id==curve.get_kmip_code()) return curve;
  }
  crypto::error("Curve not found, kmip-code=" + strext::itoa(kmip_id));
  return nullptr;
}

static bool eq_points(const EC_GROUP* g1, const EC_POINT* p1, const EC_GROUP* g2, const EC_POINT* p2)
{
  bn_t x1, y1, x2, y2;
  EC_POINT_get_affine_coordinates_GFp(g1, p1, x1, y1, NULL);
  EC_POINT_get_affine_coordinates_GFp(g2, p2, x2, y2, NULL);
  return x1==x2 && y1==y2;
}

ecurve_t ecurve_t::find(const EC_GROUP* group)
{
  int name_id = EC_GROUP_get_curve_name(group);
  if (name_id) return find(name_id);

  for (int i = 0; i<_countof(g_curves); i++)
  {
    ecurve_t curve = ecurve_t(g_curves+i);
    const EC_GROUP* curve_group = curve.get_group();
    if (!curve_group) continue;

    if (eq_points(group, EC_GROUP_get0_generator(group), curve_group, EC_GROUP_get0_generator(curve_group))) return curve;
  }
  crypto::error("Curve not found by GROUP");
  return nullptr;
}

int ecurve_t::get_der_point_size() const
{
  int n = get_oct_point_size();
  int h = out_der_header(nullptr);
  return h + n;
}

buf_t ecurve_t::octet_string_to_der(const_byte_ptr octet_string) const
{
  buf_t result;
  octet_string_to_der(octet_string, result.resize(octet_string_to_der(octet_string, NULL)));
  return result;
}

int ecurve_t::out_der_header(byte_ptr out) const
{
  int n = get_oct_point_size();

  if (out) 
  {
    *out++ = 4;
    if (n>127) *out++ = 0x81;
    *out = (uint8_t)n;
  }

  return (n>127) ? 3 : 2;
}


int ecurve_t::octet_string_to_der(const_byte_ptr octet_string, byte_ptr out) const
{
  int n = get_oct_point_size();
  int h = out_der_header(out);
  if (out) memmove(out+h, octet_string, n);
  return h + n;
}

const_byte_ptr ecurve_t::der_to_octet_string(mem_t der) const
{
  const_byte_ptr q = der.data;
  int n = der.size;

  if (n<=0) 
  {
    ub::error(E_FORMAT, "EC-point DER error");
    return nullptr;
  }
  if (*q++ != 4) 
  {
    ub::error(E_FORMAT, "EC-point DER error");
    return nullptr; // octet string
  }
  n--;

  if (n<=0) 
  {
    ub::error(E_FORMAT, "EC-point DER error");
    return nullptr;
  }
  unsigned s = *q++;
  n--;

  if (s>=0x80)
  {
    int slen = s & 0x7f;
    if (n<slen) 
    {
      ub::error(E_FORMAT, "EC-point DER error");
      return nullptr;
    }
    n-=slen;

    s = 0;
    while (slen--) { s<<=8; s|=*q++; }
  }

  if (s!=get_oct_point_size()) 
  {
    ub::error(E_FORMAT, "EC-point DER error");
    return nullptr;
  }
  if (n!=s) 
  {
    ub::error(E_FORMAT, "EC-point DER error");
    return nullptr;
  }

  if (*q != 4) 
  {
    ub::error(E_FORMAT, "EC-point DER error");
    return nullptr;  // not compressed
  }
  return q;
}

int ecurve_t::point_to_oct(const EC_POINT* point, byte_ptr out) const
{
  int n = get_oct_point_size();
  if (out) EC_POINT_point2oct(get_group(), point, POINT_CONVERSION_UNCOMPRESSED, out, n, bn_t::tls_bn_ctx());
  return n;
}

buf_t ecurve_t::point_to_oct(const EC_POINT* point) const
{
  buf_t out(get_oct_point_size());
  point_to_oct(point, out.data());
  return out;
}

int ecurve_t::point_to_compressed_oct(const EC_POINT* point, byte_ptr out) const
{
  int n = get_compressed_oct_point_size();
  if (out) EC_POINT_point2oct(get_group(), point, POINT_CONVERSION_COMPRESSED, out, n, bn_t::tls_bn_ctx());
  return n;
}

buf_t ecurve_t::point_to_compressed_oct(const EC_POINT* point) const
{
  buf_t out(get_compressed_oct_point_size());
  point_to_compressed_oct(point, out.data());
  return out;
}

int ecurve_t::point_to_der(const EC_POINT* point, byte_ptr out) const
{
  int n = get_oct_point_size();
  int h = out_der_header(out);
  if (out) point_to_oct(point, out+h);
  return h + n;
}

buf_t ecurve_t::point_to_der(const EC_POINT* point) const
{
  buf_t out(point_to_der(point, nullptr));
  point_to_der(point, out.data());
  return out;
}

ecc_point_t ecurve_t::oct_to_point(mem_t in) const
{
  ecc_point_t result(*this);

  if (0>EC_POINT_oct2point(get_group(), result, in.data, in.size, bn_t::tls_bn_ctx())) 
  {
    openssl_error("EC_POINT_oct2point error, data-size="+strext::itoa(in.size));
    result.free();
  }

  return result;
}

ecc_point_t ecurve_t::der_to_point(mem_t in) const
{
  const_byte_ptr octet_string = der_to_octet_string(in);
  if (octet_string) return oct_to_point(mem_t(octet_string, get_oct_point_size()));

  ecc_point_t result; // invalid
  return result; 
}

void ecurve_t::get_params(bn_t& p, bn_t& a, bn_t& b) const
{
  const EC_GROUP* group = get_group();
  assert(group);

  EC_GROUP_get_curve_GFp(group, p, a, b, bn_t::tls_bn_ctx());
}

ecc_point_t ecurve_t::mul_to_generator(const bn_t& val) const
{
  ecc_point_t result(*this);
  EC_POINT_mul(get_group(), result, val, nullptr, nullptr, bn_t::tls_bn_ctx());
  return result;
}

int ecurve_t::size() const { return ub::bits_to_bytes(ptr->bits); }
int ecurve_t::get_openssl_code() const { return ptr->openssl_code; }
int ecurve_t::get_dyadic_code() const { return ptr->dyadic_code; }
int ecurve_t::get_kmip_code() const { return ptr->kmip_code; }
int ecurve_t::bits() const { return ptr->bits; }
mem_t ecurve_t::oid() const { return mem_t(ptr->oid_ptr, ptr->oid_size); }
const_char_ptr ecurve_t::get_name() const { return ptr->name; }

unsigned ecurve_t::get_magic_ecdsa_pub() const { return ptr->magic_ecdsa_pub; }
unsigned ecurve_t::get_magic_ecdsa_prv() const { return ptr->magic_ecdsa_prv; }
unsigned ecurve_t::get_magic_ecdh_pub() const { return ptr->magic_ecdh_pub; }


void ecurve_data_t::check_init_once() const
{
  if (!ub::once_begin(init_once)) return;

  group = get_optimized_curve(openssl_code);
  if (group)
  {
    generator_ptr = new ecc_generator_point_t();
    generator_ptr->curve = this;
    generator_ptr->ptr = (EC_POINT*)EC_GROUP_get0_generator(group); // never dertroyed
    
    order_ptr = new bn_t();
    EC_GROUP_get_order(group, *order_ptr, NULL);
  }

  ub::once_end(init_once);
}

const EC_GROUP* ecurve_t::get_group() const
{
  ptr->check_init_once();
  return ptr->group;
}

const bn_t& ecurve_t::order() const
{
  ptr->check_init_once();
  return *ptr->order_ptr;
}

const ecc_generator_point_t& ecurve_t::generator() const
{
  ptr->check_init_once();
  return *ptr->generator_ptr;
}

bn_t ecurve_t::get_random_value() const
{
  return bn_t::rand(order());
}

#ifdef _WIN32
buf_t ecurve_t::win32_point_to_der(const_byte_ptr point) const
{
  buf_t result;
  win32_point_to_der(point, result.resize(win32_point_to_der(point, NULL)));
  return result;
}

int ecurve_t::win32_point_to_der(const_byte_ptr point, byte_ptr out) const
{
  int n = get_oct_point_size();
  int h = out_der_header(out);
  if (out)
  {
    out[h] = 4;
    memmove(out+h+1, point, n-1);
  }
  return h+n;
}

const_byte_ptr ecurve_t::win32_der_to_point(mem_t der) const
{
  const_byte_ptr octet_string = der_to_octet_string(der);
  if (!octet_string) return nullptr;
  return octet_string+1;
}
#endif


bool ecurve_t::check(const ecc_point_t& point) const
{
  if (!point.valid()) 
  {
    crypto::error("EC-point invalid");
    return false;
  }
  if (point.get_curve()!=*this) 
  {
    crypto::error("EC-point invalid");
    return false;
  }
  if (!point.is_on_curve()) 
  {
    crypto::error("EC-point invalid");
    return false;
  }
  if (point.is_infinity()) 
  {
    crypto::error("EC-point invalid");
    return false;
  }
  return true;
}

void ecurve_t::convert(ub::converter_t& converter)
{
  int curve_code = ptr ? ptr->openssl_code : 0;
  converter.convert(curve_code);
  if (curve_code)
  {
    ecurve_t curve = ecurve_t::find(curve_code);
    if (!curve) { converter.set_error(); return; }
    ptr = curve.ptr;
  }
  else ptr = nullptr;
}


// --------------------- ecc_point_t ------------------------

ecc_point_t::ecc_point_t(ecurve_t _curve) : curve(_curve), ptr(EC_POINT_new(curve.get_group()))
{
}

ecc_point_t& ecc_point_t::operator = (const ecc_point_t& src)
{
  if (&src!=this) 
  {
    free();
    curve = src.curve;
    ptr = EC_POINT_dup(src, src.curve.get_group());
  }
  return *this;
}

ecc_point_t& ecc_point_t::operator = (ecc_point_t&& src)  //move assignment
{
  if (&src!=this) 
  {
    free();
    curve = src.curve;
    ptr = src.ptr;
    src.ptr = nullptr;
  }
  return *this;
}

ecc_point_t::ecc_point_t(ecurve_t _curve, const EC_POINT* _ptr) : curve(_curve), ptr(EC_POINT_dup(_ptr, curve.get_group()))
{
}


ecc_point_t::ecc_point_t(ecurve_t _curve, const bn_t& x, const bn_t& y) : curve(_curve), ptr(EC_POINT_new(curve.get_group()))
{
  set_coordinates(x, y);
}


void ecc_point_t::free()
{
  if (!ptr) return;
  EC_POINT_free(ptr);
  ptr = nullptr;
}

ecc_point_t::ecc_point_t(const ecc_point_t& src) : curve(nullptr), ptr(nullptr)
{
  if (!src.valid()) return;
  curve = src.curve;
  ptr = EC_POINT_dup(src, src.curve.get_group());
}

ecc_point_t::ecc_point_t(ecc_point_t&& src) //move constructor
{
  curve = src.curve;
  ptr = src.ptr;
  src.ptr = nullptr;
}

void ecc_point_t::attach(ecurve_t _curve, EC_POINT* value)
{
  free();
  curve = _curve;
  ptr = value;
}


int ecc_point_t::to_oct(byte_ptr out) const 
{ 
  return curve.point_to_oct(ptr, out); 
}

int ecc_point_t::to_compressed_oct(byte_ptr out) const 
{ 
  return curve.point_to_compressed_oct(ptr, out); 
}

ecc_point_t ecc_point_t::from_oct(ecurve_t curve, mem_t in) // static
{
  return curve.oct_to_point(in);
}

int ecc_point_t::to_der(byte_ptr out) const
{
  return curve.point_to_der(ptr, out);
}

ecc_point_t ecc_point_t::from_der(ecurve_t curve, mem_t in) // static
{
  return curve.der_to_point(in);
}

void ecc_point_t::convert(ub::converter_t& converter)
{
  ecurve_t c = curve; c.convert(converter);
  if (!c) return;

  short value_size;

  value_size = c.get_compressed_oct_point_size();
  converter.convert(value_size);

  if (converter.is_write())
  {
    if (!converter.is_calc_size()) to_compressed_oct(converter.current());
  }
  else
  {
    if (value_size<0) { converter.set_error(); return; }
    if (converter.is_error() || !converter.at_least(value_size)) { converter.set_error(); return; }
    free();
    curve = c;
    const EC_GROUP* group = curve.get_group();
    ptr = EC_POINT_new(group);
    if (0>=EC_POINT_oct2point(group, *this, converter.current(), value_size, bn_t::tls_bn_ctx())) 
    { 
      openssl_error("EC_POINT_oct2point failed, size="+strext::itoa(value_size));
      converter.set_error(); 
      return; 
    }
  }

  converter.forward(value_size);
}

void ecc_point_t::get_projective_coordinates(bn_t& x, bn_t& y, bn_t& z)
{
  EC_POINT_get_Jprojective_coordinates_GFp(curve.get_group(), *this, x, y, z, bn_t::tls_bn_ctx());
}

void ecc_point_t::get_coordinates(bn_t& x, bn_t& y) const
{
  EC_POINT_get_affine_coordinates_GFp(curve.get_group(), *this, x, y, bn_t::tls_bn_ctx());
}

bn_t ecc_point_t::get_x() const
{
  bn_t x;
  get_x(x);
  return x;
}

bn_t ecc_point_t::get_y() const
{
  bn_t y;
  get_y(y);
  return y;
}

void ecc_point_t::get_x(bn_t& x) const
{
  EC_POINT_get_affine_coordinates_GFp(curve.get_group(), *this, x, nullptr, bn_t::tls_bn_ctx());
}
void ecc_point_t::get_y(bn_t& y) const
{
  EC_POINT_get_affine_coordinates_GFp(curve.get_group(), *this, nullptr, y, bn_t::tls_bn_ctx());
}

void ecc_point_t::set_coordinates(const bn_t& x, const bn_t& y)
{
  EC_POINT_set_affine_coordinates_GFp(curve.get_group(), *this, x, y, bn_t::tls_bn_ctx());
}

bool ecc_point_t::set_compressed_coordinates(const bn_t& x, int y_bits)
{
  if (0<EC_POINT_set_compressed_coordinates_GFp(curve.get_group(), *this, x, y_bits, bn_t::tls_bn_ctx())) return true;
  openssl_error("EC_POINT_set_compressed_coordinates_GFp failed");
  return false;
}

bool ecc_point_t::is_on_curve() const
{
  return 0<EC_POINT_is_on_curve(curve.get_group(), *this, bn_t::tls_bn_ctx());
}

bool ecc_point_t::is_infinity() const
{
  return 0<EC_POINT_is_at_infinity(curve.get_group(), ptr);
}

void ecc_point_t::set_infinity()
{
  EC_POINT_set_to_infinity(curve.get_group(), ptr);
}


ecc_point_t ecc_point_t::add(const ecc_point_t& val1, const ecc_point_t& val2) // static 
{
  ecc_point_t result(val1.curve);
  EC_POINT_add(val1.curve.get_group(), result, val1, val2, bn_t::tls_bn_ctx());
  return result;
}

ecc_point_t ecc_point_t::sub(const ecc_point_t& val1, const ecc_point_t& val2) // static 
{
  ecc_point_t result(val1.curve);
  ecc_point_t temp = val2;
  temp.invert();
  EC_POINT_add(val1.curve.get_group(), result, val1, temp, bn_t::tls_bn_ctx());

  return result;
}

ecc_point_t ecc_point_t::mul(const ecc_point_t& val1, const bn_t& val2) // static
{
  ecc_point_t result(val1.curve);
  EC_POINT_mul(val1.curve.get_group(), result, nullptr, val1, val2, bn_t::tls_bn_ctx());
  return result;
}

ecc_point_t operator + (const ecc_point_t& val1, const ecc_point_t& val2)
{
  return ecc_point_t::add(val1, val2);
}

ecc_point_t operator - (const ecc_point_t& val1, const ecc_point_t& val2)
{
  return ecc_point_t::sub(val1, val2);
}

ecc_point_t operator * (const ecc_point_t& val1, const bn_t& val2)
{
  return ecc_point_t::mul(val1, val2);
}

ecc_point_t operator * (const ecc_generator_point_t& val1, const bn_t& val2)
{
  return val1.curve.mul_to_generator(val2);
}

ecc_point_t& ecc_point_t::operator += (const ecc_point_t& val)
{
  EC_POINT_add(curve.get_group(), *this, *this, val, bn_t::tls_bn_ctx());
  return *this;
}

ecc_point_t& ecc_point_t::operator -= (const ecc_point_t& val)
{ 
  ecc_point_t temp = val;
  temp.invert();
  EC_POINT_add(curve.get_group(), *this, *this, temp, bn_t::tls_bn_ctx());

  return *this;
}

ecc_point_t& ecc_point_t::operator *= (const bn_t& val)
{
  EC_POINT_mul(curve.get_group(), *this, nullptr, *this, val, bn_t::tls_bn_ctx());
  return *this;
}

void ecc_point_t::invert()
{
  EC_POINT_invert(curve.get_group(), *this, bn_t::tls_bn_ctx());
}

ecc_point_t ecc_point_t::mul(const bn_t& n, const ecc_point_t& Q, const bn_t& m) // static
{
  ecc_point_t result(Q.curve);
 
  EC_POINT_mul(Q.curve.get_group(), result, n, Q, m, bn_t::tls_bn_ctx()); 
  return result;
}

ecc_point_t ecc_point_t::mul(const bn_t& n, const std::vector<ecc_point_t>& Q, const std::vector<bn_t>& m) //static
{
  ecurve_t curve = Q[0].curve;
  int count = (int)Q.size();
  assert(count==(int)m.size());
  ecc_point_t result(curve);

  typedef const EC_POINT* CONST_EC_POINT_PTR;
  CONST_EC_POINT_PTR* pt_tab = new CONST_EC_POINT_PTR [count];
  for (int i=0; i<count; i++) pt_tab[i] = Q[i];

  typedef const BIGNUM* CONST_BIGNUM_PTR;
  CONST_BIGNUM_PTR* bn_tab = new CONST_BIGNUM_PTR [count];
  for (int i=0; i<count; i++) bn_tab[i] = m[i];

  EC_POINTs_mul(curve.get_group(), result, n, count, pt_tab, bn_tab, bn_t::tls_bn_ctx());

  delete[] bn_tab;
  delete[] pt_tab;

  return result;
}

ecc_point_t ecc_point_t::mul(const std::vector<ecc_point_t>& Q, const std::vector<bn_t>& m) //static
{
  ecurve_t curve = Q[0].curve;
  int count = (int)Q.size();
  assert(count==(int)m.size());
  ecc_point_t result(curve);

  typedef const EC_POINT* CONST_EC_POINT_PTR;
  CONST_EC_POINT_PTR* pt_tab = new CONST_EC_POINT_PTR [count];
  for (int i=0; i<count; i++) pt_tab[i] = Q[i];

  typedef const BIGNUM* CONST_BIGNUM_PTR;
  CONST_BIGNUM_PTR* bn_tab = new CONST_BIGNUM_PTR [count];
  for (int i=0; i<count; i++) bn_tab[i] = m[i];

  EC_POINTs_mul(curve.get_group(), result, nullptr, count, pt_tab, bn_tab, bn_t::tls_bn_ctx());

  delete[] bn_tab;
  delete[] pt_tab;

  return result;
}

bool ecc_point_t::operator == (const ecc_point_t& val) const
{
  return 0==EC_POINT_cmp(curve.get_group(), *this, val, bn_t::tls_bn_ctx());
}

bool ecc_point_t::operator != (const ecc_point_t& val) const
{
  return 0!=EC_POINT_cmp(curve.get_group(), *this, val, bn_t::tls_bn_ctx());
}

// ----------------------- ecc_key_t ------------------------

void ecc_key_t::free()
{
  if (ptr) EC_KEY_free(ptr);
  ptr = nullptr;
}

ecc_key_t::ecc_key_t(const ecc_key_t& src) : ptr(EC_KEY_dup(src.ptr))
{
}

ecc_key_t::ecc_key_t(ecc_key_t&& src) // move
{
  curve = src.curve;
  ptr = src.ptr;
  src.ptr = nullptr;
}

ecc_key_t& ecc_key_t::operator = (const ecc_key_t& src)
{
  if (&src!=this)
  {
    free();
    curve = src.curve;
    ptr = src.ptr;
    if (ptr) EC_KEY_up_ref(ptr);
  }
  return *this;
}

ecc_key_t& ecc_key_t::operator = (ecc_key_t&& src)  //move assignment
{
  if (&src!=this)
  {
    free();
    curve = src.curve;
    ptr = src.ptr;
    src.ptr = nullptr;
  }
  return *this;
}

bool ecc_key_t::from_evp_key(EVP_PKEY *key)
{
  free();
  bool result = false;
  ptr = EVP_PKEY_get1_EC_KEY(key);
  if (ptr)
  {
    curve = ecurve_t::find(EC_KEY_get0_group(ptr));
    if (curve) 
    {
      EC_KEY_set_group(ptr, curve.get_group());
      result = true;
    }
    else free();
  }
  else
  { 
    openssl_error("EVP_PKEY_get1_EC_KEY error");
  }
  return result;
}

void ecc_key_t::attach(EC_KEY* value)
{ 
  free(); 
  curve = ecurve_t::find(EC_KEY_get0_group(value));
  if (curve) ptr = value;
}


void ecc_key_t::generate(ecurve_t _curve)
{
  free();
  const EC_GROUP* group = _curve.get_group();
  if (!group) return;

  curve = _curve;
  ptr = EC_KEY_new_by_curve_name(curve.get_openssl_code());

  assert(EC_KEY_generate_key(ptr));

  EC_POINT* point = EC_POINT_new(group);
  EC_POINT_copy(point, EC_GROUP_get0_generator(group));
  EC_POINT_mul(group, point, EC_KEY_get0_private_key(ptr), NULL, NULL, NULL);
  EC_KEY_set_public_key(ptr, point);
}

bn_t ecc_key_t::get_prv_key() const
{
  return bn_t(EC_KEY_get0_private_key(ptr));
}

buf_t ecc_key_t::get_prv_key_buf() const
{
  bn_t d = get_prv_key();
  return d.to_bin(curve.size());
}

ecc_point_t ecc_key_t::get_pub_key() const
{
  const EC_POINT* p =  EC_KEY_get0_public_key(ptr);
  if (p) return ecc_point_t(curve, p);

  const EC_GROUP* group = curve.get_group();
  ecc_point_t result(curve, EC_GROUP_get0_generator(group));
  EC_POINT_mul(group, result, EC_KEY_get0_private_key(ptr), NULL, NULL, NULL);
  return result;
}

void ecc_key_t::set_pub_key_der(ecurve_t curve, mem_t pub_key) // der 
{
  ecc_point_t point = curve.der_to_point(pub_key);
  set_pub_key(point);
}

void ecc_key_t::set_pub_key(const ecc_point_t& pub_key)
{
  free();
  if (!pub_key.valid()) return;

  curve = pub_key.curve;

  ptr = EC_KEY_new_by_curve_name(curve.get_openssl_code());
  EC_KEY_set_public_key(ptr, EC_POINT_dup(pub_key, curve.get_group()));
}

void ecc_key_t::set_prv_key(ecurve_t _curve, const bn_t& prv_key)
{
  free();
  const EC_GROUP* group = _curve.get_group();
  if (!group) return;

  curve = _curve;
  ptr = EC_KEY_new_by_curve_name(curve.get_openssl_code());

  EC_KEY_set_private_key(ptr, prv_key);

  EC_POINT* point = EC_POINT_new(group);
  EC_POINT_copy(point, EC_GROUP_get0_generator(group));
  EC_POINT_mul(group, point, EC_KEY_get0_private_key(ptr), NULL, NULL, NULL);
  EC_KEY_set_public_key(ptr, point);
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000
#define OPENSSL_ECDSA_SIG_PTR
#endif

ecdsa_signature_t ecc_key_t::ecdsa_sign(mem_t in)
{
  ECDSA_SIG* sig = ECDSA_do_sign(in.data, in.size, ptr);
  assert(sig);
  
  bn_t r, s;
#ifdef OPENSSL_ECDSA_SIG_PTR
  const BIGNUM* pr = nullptr;
  const BIGNUM* ps = nullptr;
  ECDSA_SIG_get0(sig, &pr, &ps);
  r = pr;
  s = ps;
#else
  r = sig->r; 
  s = sig->s; 
#endif
  ECDSA_SIG_free(sig);

  return ecdsa_signature_t(curve, r, s);
}

bool ecc_key_t::ecdsa_verify(mem_t in, const ecdsa_signature_t& signature)
{
  if (signature.curve!=curve) return false;

#ifdef OPENSSL_ECDSA_SIG_PTR
  ECDSA_SIG* sig_ptr = ECDSA_SIG_new();
  ECDSA_SIG_set0(sig_ptr, BN_dup(signature.r), BN_dup(signature.s));
#else
  ECDSA_SIG sig = { (BIGNUM*)(const BIGNUM*)signature.r, (BIGNUM*)(const BIGNUM*)signature.s }; 
  ECDSA_SIG* sig_ptr = &sig;
#endif

  bool result  = (1==ECDSA_do_verify(in.data, in.size, sig_ptr, ptr));
  if (!result)
  {
    openssl_error("ECDSA_do_verify error data-size=" + strext::itoa(in.size));
  }

#ifdef OPENSSL_ECDSA_SIG_PTR
  ECDSA_SIG_free(sig_ptr);
#endif

  return result;
}

ecdsa_signature_t ecdsa_signature_t::from_bin(ecurve_t curve, mem_t in) //static 
{
  bn_t r, s;
  int curve_size = curve.size();
  if (in.size==curve_size*2)
  {
    r = bn_t::from_bin(mem_t(in.data,            curve_size));
    s = bn_t::from_bin(mem_t(in.data+curve_size, curve_size));
  }
  return ecdsa_signature_t(curve, r, s);
}

ecdsa_signature_t ecdsa_signature_t::from_der(ecurve_t curve, mem_t in) // static 
{
  const_byte_ptr in_ptr = in.data;
  bn_t r, s;

#ifdef OPENSSL_ECDSA_SIG_PTR
  ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, &in_ptr, in.size);
  if (sig)
  {
    const BIGNUM* pr = nullptr;
    const BIGNUM* ps = nullptr;
    ECDSA_SIG_get0(sig, &pr, &ps);
    r = pr;
    s = ps;
  }
#else
  ECDSA_SIG sig = {(BIGNUM*)r, (BIGNUM*)s};
  ECDSA_SIG* sig_ptr = &sig;
  d2i_ECDSA_SIG(&sig_ptr, &in_ptr, in.size);
#endif
  return ecdsa_signature_t(curve, r, s);
}

int ecdsa_signature_t::to_bin(byte_ptr out) const
{
  if (!valid()) return -1;
  int curve_size = curve.size();
  int r_size = r.get_bin_size();
  int s_size = s.get_bin_size();
  if (r_size>curve_size || s_size>curve_size) return -1;

  if (out)
  {
    r.to_bin(out,            curve_size);
    s.to_bin(out+curve_size, curve_size);
  }
  return curve_size*2;
}

int ecdsa_signature_t::to_der(byte_ptr out) const
{
#ifdef OPENSSL_ECDSA_SIG_PTR
  ECDSA_SIG* sig_ptr = ECDSA_SIG_new();
  ECDSA_SIG_set0(sig_ptr, BN_dup(r), BN_dup(s));
#else
  ECDSA_SIG sig = {(BIGNUM*)(const BIGNUM*)r, (BIGNUM*)(const BIGNUM*)s};
  ECDSA_SIG* sig_ptr = &sig;
#endif

  int out_size = i2d_ECDSA_SIG(sig_ptr, NULL);

  if (out_size>0 && out) i2d_ECDSA_SIG(sig_ptr, &out);

#ifdef OPENSSL_ECDSA_SIG_PTR
  ECDSA_SIG_free(sig_ptr);
#endif

  if (out_size<=0)  return -1;
  return out_size;
}

buf_t ecdsa_signature_t::to_bin() const
{
  int out_size = to_bin(nullptr);
  if (out_size<=0) return buf_t();
  buf_t out(out_size);
  to_bin(out.data());
  return out;
}

buf_t ecdsa_signature_t::to_der() const
{
  int out_size = to_der(nullptr);
  if (out_size<=0) return buf_t();
  buf_t out(out_size);
  to_der(out.data());
  return out;
}

void ecdsa_signature_t::convert(ub::converter_t& converter)
{
  converter.convert(curve);
  converter.convert(r);
  converter.convert(s);
}

int ecdsa_signature_t::get_recovery_code(mem_t in, const ecc_point_t& pub_key)
{
  int curve_size = curve.size();
  if (in.size >= curve_size) in.size = curve.size();
  bn_t e = bn_t::from_bin(in);

  buf_t oct(1+curve_size);
  oct[0] = 2;
  r.to_bin(oct.data()+1, curve_size);
  ecc_point_t R = curve.oct_to_point(oct);
  if (!curve.check(R)) return -1;

  const bn_t& order = curve.order();
  const ecc_generator_point_t& G = curve.generator();

  bn_t r_inv = r.inverse_mod(order);

  ecc_point_t Q = (R*s - G*e) * r_inv;
  if (Q == pub_key) return 0;
  
  R.invert();
  Q = (R*s - G*e) * r_inv;
  if (Q == pub_key) return 1;

  return -1;
}

ecc_point_t ecdsa_signature_t::recover_pub_key(mem_t in, int recovery_code)
{
  if (recovery_code!=0 && recovery_code!=1) return ecc_point_t();

  int curve_size = curve.size();
  if (in.size >= curve_size) in.size = curve.size();
  bn_t e = bn_t::from_bin(in);

  buf_t oct(1+curve_size);
  oct[0] = 2 + recovery_code;
  r.to_bin(oct.data()+1, curve_size);
  ecc_point_t R = curve.oct_to_point(oct);
  if (!curve.check(R)) return ecc_point_t();

  const bn_t& order = curve.order();
  const ecc_generator_point_t& G = curve.generator();
  bn_t r_inv = r.inverse_mod(order);
  return (R*s - G*e) * r_inv;
}



void ecc_key_t::ecdh(const ecc_point_t& pub_key, byte_ptr out) const
{
  assert(0<=ECDH_compute_key(out, curve.size(), pub_key, ptr, NULL));
}

buf_t ecc_key_t::ecdh(const ecc_point_t& pub_key) const
{
  buf_t out(curve.size());
  ecdh(pub_key, out.data());
  return out;
}


buf_t ecc_key_t::export_pub_key_info() const
{
  EC_KEY_set_asn1_flag(ptr, OPENSSL_EC_NAMED_CURVE);
    
  buf_t out;
  int out_size = i2d_EC_PUBKEY(ptr, nullptr); 
  if (out_size>0) 
  {
    byte_ptr out_ptr = out.resize(out_size);
    i2d_EC_PUBKEY(ptr, &out_ptr);
  }
    
  return out;
}

ecc_key_t ecc_key_t::import_pub_key_info(mem_t in)
{
	ecc_key_t ecc;

	const_byte_ptr src = in.data;
  EC_KEY* ptr = d2i_EC_PUBKEY(NULL, &src, in.size);
  if (ptr) ecc.attach(ptr);

  return ecc;
}

ecc_key_t ecc_key_t::import_pkcs8_prv(mem_t in)
{
  ecc_key_t ecc;

  const_byte_ptr src = in.data;
  ub::scoped_ptr_t<PKCS8_PRIV_KEY_INFO> pkcs8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &src, in.size);
  if (!pkcs8) 
  {
    openssl_error("d2i_PKCS8_PRIV_KEY_INFO error, data-size="+strext::itoa(in.size));
    return ecc;
  }

  EVP_PKEY* evp = EVP_PKCS82PKEY(pkcs8);
  if (!evp) 
  {
    openssl_error("EVP_PKCS82PKEY error");
    return ecc;
  }

  ecc.ptr = EVP_PKEY_get1_EC_KEY(evp);
  if (!ecc.ptr)
  {
    openssl_error("EVP_PKEY_get1_RSA error");
  }

  return ecc;
}

buf_t ecc_key_t::export_pkcs8_prv() const
{
  EC_KEY_set_asn1_flag(ptr, OPENSSL_EC_NAMED_CURVE);

  ub::scoped_ptr_t<EVP_PKEY> evp = EVP_PKEY_new();
  EVP_PKEY_set1_EC_KEY(evp, ptr);

  ub::scoped_ptr_t<PKCS8_PRIV_KEY_INFO> pkcs8 = EVP_PKEY2PKCS8(evp);
  int size = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, NULL);
  buf_t result(size);
  byte_ptr dst = result.data();
  i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &dst);

  return result;
}


// ---------------------------------- EC25519 ----------------------------

static const byte_t ed25519_order_bin[] = {
    //l: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed};

static ub::once_t ec25519_once_init = ub::once_init;
static ecp_gen_25519_t ecp_gen_25519;

const ecp_gen_25519_t& ec25519::generator() 
{
  if (ub::once_begin(ec25519_once_init)) 
  {
    uint8_t one[32] = {1, 0};
    ec25519_core::ge_scalarmult_base(&ecp_gen_25519.ge_p3, one);  
    ub::once_end(ec25519_once_init);
  }
  return ecp_gen_25519;
}

bn_t ec25519::order()
{
  return bn_t::from_bin(mem_t(ed25519_order_bin, sizeof(ed25519_order_bin)));
}

ecp_25519_t operator * (const ecp_gen_25519_t& G, const bn_t& val)
{
  return ec25519::mul_to_generator(val);
}

ecp_25519_t ec25519::mul_to_generator(const bn_t& val)
{
  byte_t scalar[32];
  ec25519::encode_scalar(val, scalar);

  ecp_25519_t result;
  ec25519_core::ge_scalarmult_base(&result.ge_p3, scalar);  

  ub::secure_bzero(scalar);
  return result;
}

bool ecp_25519_t::operator == (const ecp_25519_t& val) const
{
  byte_t encoded1[32];
  byte_t encoded2[32];
  encode(encoded1);
  val.encode(encoded2);
  return 0==memcmp(encoded1, encoded2, 32);
}

bool ecp_25519_t::operator != (const ecp_25519_t& val) const
{
  byte_t encoded1[32];
  byte_t encoded2[32];
  encode(encoded1);
  val.encode(encoded2);
  return 0!=memcmp(encoded1, encoded2, 32);
}

ecp_25519_t operator + (const ecp_25519_t& val1, const ecp_25519_t& val2) 
{
  ecp_25519_t result;

  ec25519_core::ge_p1p1 dst_p1p1;
  ec25519_core::ge_cached src2_cached;

  ec25519_core::ge_p3_to_cached(&src2_cached, &val2.ge_p3);          // src2 p3 -> cached
  ec25519_core::ge_add(&dst_p1p1, &val1.ge_p3, &src2_cached);        // add p1p1 = p3 + cached
  ec25519_core::ge_p1p1_to_p3(&result.ge_p3, &dst_p1p1);

  return result;
}

ecp_25519_t operator - (const ecp_25519_t& val1, const ecp_25519_t& val2) 
{
  ecp_25519_t result;

  ec25519_core::ge_p1p1 dst_p1p1;
  ec25519_core::ge_cached src2_cached;

  ec25519_core::ge_p3_to_cached(&src2_cached, &val2.ge_p3);          // src2 p3 -> cached
  ec25519_core::ge_sub(&dst_p1p1, &val1.ge_p3, &src2_cached);        // sub p1p1 = p3 - cached
  ec25519_core::ge_p1p1_to_p3(&result.ge_p3, &dst_p1p1);

  return result;
}


ecp_25519_t operator * (const ecp_25519_t& val1, const bn_t& val2) 
{
  ecp_25519_t result;
  
  ec25519_core::ge_p2 p2;
  uint8_t b[32] = {0};
  uint8_t bytes[32];
  uint8_t scalar[32];

  ec25519::encode_scalar(val2, scalar);
  ec25519_core::ge_double_scalarmult_vartime(&p2, scalar, &val1.ge_p3, b);    // mul p2 = p3 * scalar + G * 0
  ec25519_core::ge_tobytes(bytes, &p2);
  ec25519_core::ge_frombytes_vartime(&result.ge_p3, bytes);

  return result;
}

void ecp_25519_t::invert()
{
  ec25519_core::ge_p1p1 dst_p1p1;
  ec25519_core::ge_cached src_cached;
  ec25519_core::ge_p3 zero;

  ec25519_core::ge_p3_0(&zero);
  ec25519_core::ge_p3_to_cached(&src_cached, &this->ge_p3);          // src2 p3 -> cached
  ec25519_core::ge_sub(&dst_p1p1, &zero, &src_cached);               // sub p1p1 = p3 - cached
  ec25519_core::ge_p1p1_to_p3(&this->ge_p3, &dst_p1p1);
}

void ecp_25519_t::convert(ub::converter_t& converter) 
{
  const int value_size = 32;
  if (converter.is_write())
  {
    if (!converter.is_calc_size()) encode(converter.current());
  }
  else
  {
    if (converter.is_error() || !converter.at_least(value_size)) { converter.set_error(); return; }
    if (!decode(converter.current())) { converter.set_error(); return; }
  }
  converter.forward(value_size);
}

bool ec25519::check(const ecp_25519_t& point) 
{
  const byte_t zeros[sizeof(ec25519_core::ge_p3)] = {0};
  return 0!=memcmp(zeros, &point.ge_p3, sizeof(ec25519_core::ge_p3));
}


// ------------------------------------ EDDSA -----------------------------
void eddsa_key_t::generate()
{
  set_prv_key(crypto::gen_random(32));
}


void eddsa_key_t::set_prv_key(mem_t prv_key)
{
  assert(prv_key.size==32);
  set_prv_key(prv_key.data);
}

ecp_25519_t eddsa_key_t::get_pub_key_point() const
{
  ecp_25519_t result;
  result.decode(pub_key);
  return result;
}

void eddsa_key_t::set_prv_key(const_byte_ptr prv_key)
{
  memmove(this->prv_key, prv_key, 32);

  byte_t encoded_prv_key[32];
  encode_prv_key(encoded_prv_key, prv_key);

  ec25519_core::ge_p3 p3;
  ec25519_core::ge_scalarmult_base(&p3, encoded_prv_key);
  ec25519_core::ge_p3_tobytes(pub_key, &p3);
  ub::secure_bzero(encoded_prv_key, 32);
}

bn_t eddsa_key_t::get_prv_key_bn() const
{
  return ec25519::decode_scalar(encode_prv_key(mem_t(prv_key, 32)));
}

void eddsa_key_t::set_pub_key(const ecp_25519_t& Q)
{
  Q.encode(pub_key);
}

void eddsa_key_t::set_pub_key(mem_t pub_key)
{
  assert(pub_key.size==32);
  set_pub_key(pub_key.data);
}

void eddsa_key_t::set_pub_key(const_byte_ptr pub_key)
{
  memmove(this->pub_key, pub_key, 32);
}

void eddsa_key_t::sign(mem_t in, byte_ptr out) const
{
  ec25519_core::ED25519_sign(out, in.data, in.size, pub_key, prv_key);
}

buf_t eddsa_key_t::sign(const bn_t& prv_key, mem_t in)
{
  buf_t scalar = ec25519::encode_scalar(prv_key);
  buf_t pub_key = ec25519::mul_to_generator(prv_key).encode();

  buf_t signature(64);
  ec25519_core::ED25519_sign_with_scalar(signature.data(), in.data, in.size, pub_key.data(), scalar.data());
  return signature;
}


buf_t eddsa_key_t::sign(mem_t in) const
{
  buf_t signature(64);
  sign(in, signature.data());
  return signature;
}

bool eddsa_key_t::verify(mem_t in, const_byte_ptr signature) const
{
  return 0 != ec25519_core::ED25519_verify(in.data, in.size, signature, pub_key);
}

bool eddsa_key_t::verify(mem_t in, mem_t signature) const
{
  if (signature.size!=64) return false;
  return verify(in, signature.data);
}

void eddsa_key_t::encode_prv_key(byte_ptr dst, const_byte_ptr src) // static
{
  uint8_t az[64];

  crypto::hash_t(crypto::hash_e::sha512).init().update(mem_t(src, 32)).final(az);

  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  memmove(dst, az, 32);
  ub::secure_bzero(az, 64);
}

buf_t eddsa_key_t::encode_prv_key(mem_t src) // static
{
  assert(src.size==32);
  buf_t out(32);
  encode_prv_key(out.data(), src.data);
  return out;
}

int ecp_25519_t::encode(byte_ptr out) const
{
  if (out) ec25519_core::ge_p3_tobytes(out, &ge_p3);
  return 32;
}

buf_t ecp_25519_t::encode() const
{
  buf_t out(32);
  encode(out.data());
  return out;
}

bool ecp_25519_t::decode(const_byte_ptr point)
{
  return 0==ec25519_core::ge_frombytes_vartime(&this->ge_p3, point);
}

bool ecp_25519_t::decode(mem_t in)
{
  if (in.size!=32) return false;
  return decode(in.data);
}

bn_t ec25519::decode_scalar(const_byte_ptr scalar)
{
  byte_t temp[32];
  memmove(temp, scalar, 32);
  mem_t mem = mem_t(temp, 32);
  mem.reverse();
  bn_t result = bn_t::from_bin(mem);
  mem.secure_bzero();
  return result;
}

bn_t ec25519::decode_scalar(mem_t scalar)
{
  assert(scalar.size==32);
  return decode_scalar(scalar.data);
}


buf_t ec25519::reduce_scalar_64(const_byte_ptr scalar64)
{
  buf_t out(32);
  reduce_scalar_64(scalar64, out.data());
  return out;
}

buf_t ec25519::reduce_scalar_64(mem_t scalar64)
{
  assert(scalar64.size==64);
  return reduce_scalar_64(scalar64.data);
}

void ec25519::reduce_scalar_64(const_byte_ptr scalar64, byte_ptr out)
{
  byte_t temp[64];
  memmove(temp, scalar64, 64);
  ec25519_core::x25519_sc_reduce(temp);
  memmove(out, temp, 32);
}

void ec25519::reduce_scalar_64(mem_t scalar64, byte_ptr out)
{
  assert(scalar64.size==64);
  reduce_scalar_64(scalar64.data, out);
}


buf_t ec25519::encode_scalar(const bn_t& val)
{
  buf_t out(32);
  encode_scalar(val, out.data());
  return out;
}

int ec25519::encode_scalar(const bn_t& val, byte_ptr out)
{
  if (out)
  {
    if (val.get_bin_size() < 32)
    {
      val.to_bin(out, 32);
      mem_t(out, 32).reverse();
    }
    else if (val.get_bin_size() > 64)
    {
      bn_t reduced = val % ec25519::order();
      reduced.to_bin(out, 32);
      mem_t(out, 32).reverse();
    }
    else
    {
      uint8_t temp[64];
      val.to_bin(temp, 64);
      mem_t(temp, 64).reverse();
      ec25519_core::x25519_sc_reduce(temp);
      memmove(out, temp, 32);
    }
  }
  return 32;
}

ecp_25519_t ec25519::mul_to_generator(const_byte_ptr scalar)
{
  ecp_25519_t out;
  ec25519_core::ge_scalarmult_base(&out.ge_p3, scalar);
  return out;
}

ecp_25519_t ec25519::mul_to_generator(mem_t scalar)
{
  assert(scalar.size==32);
  return mul_to_generator(scalar.data);
}

void ec25519::scalar_muladd(byte_ptr dst, const_byte_ptr a, const_byte_ptr b, const_byte_ptr c) //(ab+c) mod l
{
  ec25519_core::sc_muladd(dst, a, b, c);
}

buf_t ec25519::scalar_muladd(mem_t a, mem_t b, mem_t c) //(ab+c) mod l
{
  assert(a.size==32);
  assert(b.size==32);
  assert(c.size==32);

  buf_t out(32);
  scalar_muladd(out.data(), a.data, b.data, c.data);
  return out;
}


}
