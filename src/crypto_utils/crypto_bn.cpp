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

namespace crypto {

struct bn_thread_info_t
{
  const BIGNUM* modulo;
  BN_CTX* bn_ctx;

  bn_thread_info_t() : modulo(nullptr), bn_ctx(BN_CTX_new()) {}
  ~bn_thread_info_t() { BN_CTX_free(bn_ctx); }
};

static ub::tls_t<bn_thread_info_t> tls_bn_info;
static const BIGNUM* tls_modulo() { return tls_bn_info.instance().modulo; }
static void tls_set_modulo(const BIGNUM* ptr) { tls_bn_info.instance().modulo = ptr; }
 
BN_CTX* bn_t::tls_bn_ctx() // static
{
  return tls_bn_info.instance().bn_ctx;
}

bn_t::bn_t(const BIGNUM* src)
{
#ifdef OPENSSL_BN_PTR
  val_ptr = src ? BN_dup(src) : BN_new();
#else
  BN_init(*this);
  if (src) BN_copy(*this, src);
#endif
}


bn_t::bn_t()
{
#ifdef OPENSSL_BN_PTR
  val_ptr = BN_new();
#else
  BN_init(*this);
#endif
}

bn_t::bn_t(mem_t src)
{
#ifdef OPENSSL_BN_PTR
  val_ptr = BN_new();
#else
  BN_init(*this);
#endif
  BN_bin2bn(src.data, src.size, *this);
}

bn_t::bn_t(buf128_t src)
{
#ifdef OPENSSL_BN_PTR
  val_ptr = BN_new();
#else
  BN_init(*this);
#endif
  BN_bin2bn(const_byte_ptr(&src), sizeof(src), *this);
}

bn_t::bn_t(buf256_t src)
{
#ifdef OPENSSL_BN_PTR
  val_ptr = BN_new();
#else
  BN_init(*this);
#endif
  BN_bin2bn(const_byte_ptr(&src), sizeof(src), *this);
}


bn_t::~bn_t()
{
  BN_clear_free(*this);
}

bn_t::bn_t(int src)
{
#ifdef OPENSSL_BN_PTR
  val_ptr = BN_new();
#else
  BN_init(*this);
#endif

  if (src<0)
  {
    BN_set_word(*this, -src);
    BN_set_negative(*this, 1);
  }
  else
  {
    BN_set_word(*this, src);
  }
}

bn_t::bn_t(const bn_t& src) 
{
#ifdef OPENSSL_BN_PTR
  val_ptr = BN_dup(src);
#else
  BN_init(*this);
  BN_copy(*this, src);
#endif
}

bn_t::bn_t(bn_t&& src) //move constructor
{
#ifdef OPENSSL_BN_PTR
  val_ptr = src.val_ptr;
  src.val_ptr = nullptr;
#else
  val = src.val;
  memset(&src.val,  0, sizeof(src.val));
#endif
}

bn_t& bn_t::operator= (const bn_t& src)
{
  if (this!=&src) BN_copy(*this, src);
  return *this;
}

bn_t& bn_t::operator = (const BIGNUM* src)
{
  BN_copy(*this, src);
  return *this;
}


bn_t& bn_t::operator= (bn_t&& src)  //move assignment
{
  if (this!=&src)
  {
    BN_clear_free(*this);
#ifdef OPENSSL_BN_PTR
    val_ptr = src.val_ptr;
    src.val_ptr = nullptr;
#else
    val = src.val;
    memset(&src.val,  0, sizeof(src.val));
#endif
  }
  return *this;
}


#ifdef INTEL_X64
int64_t bn_t::get_int64() const
{
  int64_t result = BN_get_word(*this);
  if (BN_is_negative((const BIGNUM*)*this)) result = -result;
  return (int64_t)result;
}

void bn_t::set_int64(int64_t src)
{
  if (src<0)
  {
    BN_set_word(*this, -src);
    BN_set_negative(*this, 1);
  }
  else
  {
    BN_set_word(*this, src);
  }
}
#endif

bn_t::operator int() const
{
  int64_t result = BN_get_word(*this);
  if (BN_is_negative((const BIGNUM*)*this)) result = -result;
  return (int)result;
}

bn_t& bn_t::operator= (int src)
{
  if (src<0)
  {
    BN_set_word(*this, -src);
    BN_set_negative(*this, 1);
  }
  else
  {
    BN_set_word(*this, src);
  }
  return *this;
}

bool bn_t::operator == (const bn_t& src2) const { return compare(*this, src2)==0; }
bool bn_t::operator != (const bn_t& src2) const { return compare(*this, src2)!=0; }
bool bn_t::operator > (const bn_t& src2) const  { return compare(*this, src2) > 0; }
bool bn_t::operator < (const bn_t& src2) const  { return compare(*this, src2) < 0; }
bool bn_t::operator >= (const bn_t& src2) const  { return compare(*this, src2) >= 0; }
bool bn_t::operator <= (const bn_t& src2) const  { return compare(*this, src2) <= 0; }

bool bn_t::operator == (int src2) const { return compare(*this, bn_t(src2)) == 0; }
bool bn_t::operator != (int src2) const { return compare(*this, bn_t(src2)) != 0; }
bool bn_t::operator > (int src2) const { return compare(*this, bn_t(src2)) > 0; }
bool bn_t::operator < (int src2) const { return compare(*this, bn_t(src2)) < 0; }
bool bn_t::operator >= (int src2) const { return compare(*this, bn_t(src2)) >= 0; }
bool bn_t::operator <= (int src2) const { return compare(*this, bn_t(src2)) <= 0; }


bn_t& bn_t::operator += (const bn_t& src2)
{
  const BIGNUM* modulo = tls_modulo();
  if (modulo) BN_mod_add(*this, *this, src2, modulo,  tls_bn_ctx());
  else BN_add(*this, *this, src2);
  return *this;
}

bn_t& bn_t::operator -= (const bn_t& src2)
{
  const BIGNUM* modulo = tls_modulo();
  if (modulo) BN_mod_sub(*this, *this, src2, modulo, tls_bn_ctx());
  else BN_sub(*this, *this, src2);
  return *this;
}

bn_t& bn_t::operator *= (const bn_t& src2)
{
  const BIGNUM* modulo = tls_modulo();
  if (modulo) BN_mod_mul(*this, *this, src2, modulo, tls_bn_ctx());
  else BN_mul(*this, *this, src2, tls_bn_ctx());
  return *this;
}

bn_t& bn_t::operator /= (const bn_t& src2)
{
  const BIGNUM* modulo = tls_modulo();
  if (modulo)
  {
    bn_t temp;
    BN_mod_inverse(temp, src2, modulo, bn_t::tls_bn_ctx());
    BN_mod_mul(*this, *this, temp, modulo, bn_t::tls_bn_ctx());
  }
  else
  {
    BN_div(*this, nullptr, *this, src2,  tls_bn_ctx());
  }
  return *this;
}

bn_t& bn_t::operator %= (const bn_t& src2)
{
  BN_div(nullptr, *this, *this, src2,  tls_bn_ctx());
  return *this;
}

bn_t& bn_t::operator ++ () 
{
  const BIGNUM* modulo = tls_modulo();
  if (modulo) 
  {
    bn_t one = 1;
    BN_mod_add(*this, *this, one, modulo, tls_bn_ctx());
  }
  else BN_add_word(*this, 1);
  return *this;
}

bn_t bn_t::operator ++ (int dummy)
{
   bn_t tmp(*this); 
   operator++();
   return tmp;   
} 

bn_t& bn_t::operator += (int src2)
{
  const BIGNUM* modulo = tls_modulo();
  if (modulo) 
  {
    bn_t temp = src2;
    BN_mod_add(*this, *this, temp,  modulo,  tls_bn_ctx());
  }
  else 
  {
    if (src2>=0) BN_add_word(*this, src2);
    else BN_sub_word(*this, -src2);
  }
  return *this;
}

bn_t& bn_t::operator -= (int src2)
{
  const BIGNUM* modulo = tls_modulo();
  if (modulo) 
  {
    bn_t temp = src2;
    BN_mod_sub(*this, *this, temp, modulo,  tls_bn_ctx());
  }
  else 
  {
    if (src2>=0) BN_sub_word(*this, src2);
    else BN_add_word(*this, -src2);
  }
  return *this;
}

bn_t& bn_t::operator *= (int src2)
{
  const BIGNUM* modulo = tls_modulo();
  if (modulo) 
  {
    bn_t temp = src2;
    BN_mod_mul(*this, *this, temp, modulo, tls_bn_ctx());
  }
  else 
  {
    bool neg = src2<0;
    if (neg) src2 = -src2;
    BN_mul_word(*this, src2);
    if (neg) BN_set_negative(*this, !BN_is_negative((const BIGNUM*)*this));
  }
  return *this;
}

bn_t& bn_t::operator /= (int src2)
{
  BN_div(*this, nullptr, *this, bn_t(src2), tls_bn_ctx());
  return *this;
}

bn_t& bn_t::operator %= (int src2)
{
  BN_div(nullptr, *this, *this, bn_t(src2), tls_bn_ctx());
  return *this;
}

bn_t operator + (const bn_t& src1, const bn_t& src2)
{
  bn_t result;
  const BIGNUM* modulo = tls_modulo();
  if (modulo) BN_mod_add(result, src1, src2, modulo, bn_t::tls_bn_ctx());
  else BN_add(result, src1, src2);
  return result;
}

bn_t operator + (const bn_t& src1, int src2) 
{ 
  if (tls_modulo()) return src1 + bn_t(src2);

  bn_t result = src1;
  if (src2>=0) BN_add_word(result, src2);
  else BN_sub_word(result, -src2);
  return result;
}

bn_t operator - (const bn_t& src1, const bn_t& src2)
{
  bn_t result;
  const BIGNUM* modulo = tls_modulo();
  if (modulo) BN_mod_sub(result, src1, src2, modulo, bn_t::tls_bn_ctx());
  else BN_sub(result, src1, src2);
  return result;
}

bn_t operator - (const bn_t& src1, int src2)
{
  if (tls_modulo()) return src1 - bn_t(src2);

  bn_t result = src1;
  if (src2>=0) BN_sub_word(result, src2);
  else BN_add_word(result, -src2);
  return result;
}

bn_t operator * (const bn_t& src1, const bn_t& src2)
{
  bn_t result;
  const BIGNUM* modulo = tls_modulo();
  if (modulo) BN_mod_mul(result, src1, src2, modulo, bn_t::tls_bn_ctx());
  else BN_mul(result, src1, src2, bn_t::tls_bn_ctx());
  return result;
}

bn_t operator * (const bn_t& src1, int src2)
{
  if (tls_modulo()) return src1 * bn_t(src2);

  bn_t result = src1;
  bool neg = src2<0;
  if (neg) src2 = -src2;
  BN_mul_word(result, src2);
  if (neg) BN_set_negative(result, !BN_is_negative((const BIGNUM*)result));
  return result;
}

bn_t operator / (const bn_t& src1, const bn_t& src2)
{
  bn_t result;
  const BIGNUM* modulo = tls_modulo();
  if (modulo)
  {
    bn_t temp;
    BN_mod_inverse(temp, src2, modulo,  bn_t::tls_bn_ctx());
    BN_mod_mul(result, src1,  temp, modulo, bn_t::tls_bn_ctx());
  }
  else
  {
    BN_div(result, nullptr, src1, src2, bn_t::tls_bn_ctx());
  }
  return result;
}

bn_t operator / (const bn_t& src1, int src2)
{
  return src1 / bn_t(src2);
}

bn_t operator % (const bn_t& src1, const bn_t& src2)
{
  bn_t result;
  BN_div(nullptr, result, src1, src2, bn_t::tls_bn_ctx());
  return result;
}

bn_t operator % (const bn_t& src1, int src2)
{
  return src1 % bn_t(src2);
}

bn_t operator - (const bn_t& src1)
{
  return src1.neg();
}

bn_t bn_t::pow(const bn_t& src1, const bn_t& src2) // static
{
  const BIGNUM* modulo = tls_modulo();
  if (modulo) 
  {
    if (src2.sign() < 0) return pow_mod(src1.inv(), src2.neg(), modulo);

    bn_t result;
    BN_mod_exp(result, src1, src2, modulo, tls_bn_ctx());
    return result;
  }

  bn_t result;
  BN_exp(result, src1, src2,  tls_bn_ctx());
  return result;
}

bn_t bn_t::div(const bn_t& src1, const bn_t& src2, bn_t* rem) //static
{
  bn_t result;
  BIGNUM* rem_bn = rem ? (BIGNUM*)*rem : (BIGNUM*)nullptr;
  BN_div(result, rem_bn, src1, src2, tls_bn_ctx());
  return result;
}

bn_t bn_t::mod(const bn_t& src1, const bn_t& src2) //static
{
  bn_t result;
  BN_div(nullptr, result, src1, src2, tls_bn_ctx());
  return result;
}

bn_t bn_t::sqr(const bn_t& src1) { return src1.sqr(); } // static 
bn_t bn_t::abs(const bn_t& src1) { return src1.abs(); } // static 
bn_t bn_t::neg(const bn_t& src1) { return src1.neg(); } // static 

bn_t bn_t::sqr() const
{
  bn_t result;
  BN_sqr(result, *this, tls_bn_ctx());
  return result;
}


bn_t bn_t::sqrt_floor() const // newton's method
{
  if (sign()<0) return 0;
  
  const bn_t& n = *this;
  bn_t xn = 1;
  bn_t xn1 = (xn + n/xn)/2;

  while (abs(xn1 - xn) > 1)  
  {
    xn = xn1;
    xn1 = (xn + n/xn)/2;
  }
  
  while (xn1*xn1 > n)
  {
    xn1 -= 1;
  }
  return xn1;
}

bn_t& bn_t::operator <<= (int value)
{
  BN_lshift(*this, *this, value);
  return *this;
}

bn_t& bn_t::operator >>= (int value)
{
  BN_rshift(*this, *this, value);
  return *this;
}

bn_t bn_t::lshift(int n) const
{
  bn_t result;
  BN_lshift(result, *this, n);
  return result;
}

bn_t bn_t::rshift(int n) const
{
  bn_t result;
  BN_rshift(result, *this, n);
  return result;
}

void bn_t::set_bit(int n, bool bit)
{
  if (bit) BN_set_bit(*this, n);
  else BN_clear_bit(*this, n);
}

bool bn_t::is_bit_set(int n) const
{
  if (BN_is_bit_set(*this, n)) return true;
  return false;
}

bool bn_t::is_odd() const
{
  return BN_is_odd((const BIGNUM*)*this) ? true : false;
}

bool bn_t::is_zero() const
{
  return BN_is_zero((const BIGNUM*)*this) ? true : false;
}

bn_t bn_t::neg() const
{
  if (BN_is_zero((const BIGNUM*)*this)) return *this;
  bn_t result = *this;
  BN_set_negative(result, !BN_is_negative((const BIGNUM*)*this));
  return result;
}

bn_t bn_t::abs() const
{
  return (*this >= 0) ? *this : neg();
}

bn_t bn_t::rand(int bits, bool top_bit_set)
{
  bn_t result;
  int top = top_bit_set ? 1 : -1;
  BN_rand(result, bits, top, 0);
  return result;
}

bn_t bn_t::rand(const bn_t& range) //static
{
  bn_t result;
  BN_rand_range(result, range);
  return result;
}

bn_t bn_t::add_mod(const bn_t& src1, const bn_t& src2, const bn_t& mod) // static 
{
  bn_t result;
  BN_mod_add(result, src1, src2, mod, tls_bn_ctx());
  return result;
}

bn_t bn_t::add_mod_quick(const bn_t& src1, const bn_t& src2, const bn_t& mod) // both src1 and src2 are non-negative and less than mod
{
  bn_t result;
  BN_mod_add_quick(result, src1, src2, mod);
  return result;
}

bn_t bn_t::sub_mod(const bn_t& src1, const bn_t& src2, const bn_t& mod) // static 
{
  bn_t result;
  BN_mod_sub(result, src1, src2, mod, tls_bn_ctx());
  return result;
}

bn_t bn_t::mul_mod(const bn_t& src1, const bn_t& src2, const bn_t& mod) // static 
{
  bn_t result;
  BN_mod_mul(result, src1, src2, mod, tls_bn_ctx());
  return result;
}

bn_t bn_t::pow_mod(const bn_t& src1, const bn_t& src2, const bn_t& mod) // static 
{
  return pow_mod(src1, src2, (const BIGNUM*)mod);
}

bn_t bn_t::pow_mod(const bn_t& src1, const bn_t& src2, const BIGNUM* mod) // static 
{
  if (src2.sign() < 0)
    return pow_mod(inverse_mod(src1, mod), src2.neg(), mod);

  bn_t result;
  BN_mod_exp(result, src1, src2, mod, tls_bn_ctx());
  return result;
}

bn_t bn_t::inv() const // only valid for modulo
{
  const BIGNUM* modulo = tls_modulo();
  assert(modulo);
  bn_t result;
  BN_mod_inverse(result, *this, modulo, tls_bn_ctx());
  return result;
}

bn_t bn_t::inverse_mod(const bn_t& src, const bn_t& mod)
{
  bn_t result;
  BN_mod_inverse(result, src, mod, tls_bn_ctx());
  return result;
}

int bn_t::get_bit(int n) const
{
  return BN_is_bit_set(*this, n);
}

int bn_t::get_bin_size() const
{
  return BN_num_bytes(*this);
}

int bn_t::get_bits_count() const
{
  return BN_num_bits(*this);
}


int bn_t::to_bin(byte_ptr dst) const
{
  return BN_bn2bin(*this, dst);
}

void bn_t::to_bin(byte_ptr dst, int size) const
{
  int bin_size = get_bin_size();
  assert(size>=bin_size);
  memset(dst, 0, size);
  to_bin(dst + size-bin_size);
}

buf_t bn_t::to_bin() const
{
  buf_t out(get_bin_size());
  to_bin(out.data());
  return out;
}

buf_t bn_t::to_bin(int size) const
{
  buf_t out(size);
  to_bin(out.data(), size);
  return out;
}

bn_t bn_t::from_bin(mem_t mem) // static 
{
  bn_t result;
  BN_bin2bn(mem.data, mem.size, result);
  return result;
}

bn_t bn_t::from_double(double value) // static 
{
  uint8_t buf[512]; 
  byte_ptr ptr = buf+sizeof(buf);
  int n = 0;

  int neg = value<0;
  if (neg) value = -value;

  value = floor(value);

  while (value)
  {
    double div = floor(value / 256);
    uint8_t rem = (uint8_t)fmod(value, 256);
    n++;
    *--ptr = rem;
    value = div;
  }

  bn_t result = from_bin(mem_t(ptr, n));
  if (neg) BN_set_negative(result, 1);
  return result;
}

int bn_t::get_mpi_size() const
{
  return BN_bn2mpi(*this, nullptr);
}

buf_t bn_t::to_mpi() const
{
  buf_t out(get_mpi_size());
  to_mpi(out.data());
  return out;
}

int bn_t::to_mpi(byte_ptr dst) const
{
  return BN_bn2mpi(*this, dst);
}

bn_t bn_t::from_mpi(mem_t mem) //static
{
  bn_t result;
  BIGNUM* b = BN_mpi2bn(mem.data, mem.size, result);
  assert(NULL!=b);
  return result;
}

std::string bn_t::to_string() const
{
  char* s = BN_bn2dec(*this);
  std::string result = s;
  OPENSSL_free(s);
  return result;
}

std::string bn_t::to_hex() const
{
  char* s = BN_bn2hex(*this);
  std::string result = s;
  OPENSSL_free(s);
  return result;
}

bn_t bn_t::from_string(const_char_ptr str)
{
  bn_t result;
  BIGNUM* ptr = result;
  int res = BN_dec2bn(&ptr, str);
  assert(0!=res);
  return result;
}

bn_t bn_t::from_hex(const_char_ptr str)
{
  bn_t result;
  BIGNUM* ptr = result;
  int res = BN_hex2bn(&ptr, str);
  assert(0!=res);
  return result;
}

int bn_t::compare(const bn_t& src1, const bn_t& src2) //static
{
  return BN_cmp(src1, src2);
}

int bn_t::sign() const
{
  if (BN_is_zero((const BIGNUM*)*this)) return 0;
  if (BN_is_negative((const BIGNUM*)*this)) return -1; 
  return +1;
}

bn_t operator << (const bn_t& src1, int src2)
{
  bn_t result;
  BN_lshift(result, src1, src2);
  return result;
}

bn_t operator >> (const bn_t& src1, int src2)
{
  bn_t result;
  BN_rshift(result, src1, src2);
  return result;
}

void bn_t::convert(ub::converter_t& converter)
{
  int8_t s_value = int8_t(sign());
  converter.convert(s_value);

  short value_size = get_bin_size();
  converter.convert(value_size);

  if (converter.is_write())
  {
    if (!converter.is_calc_size()) to_bin(converter.current());
  }
  else
  {
    if (s_value<-1 || s_value>+1) { converter.set_error(); return; }
    if (value_size<0) { converter.set_error(); return; }
    if (converter.is_error() || !converter.at_least(value_size)) { converter.set_error(); return; }
    BN_bin2bn(converter.current(), value_size, *this);
    BN_set_negative(*this, s_value<0);
  }
  converter.forward(value_size);
}


bn_t bn_t::generate_prime(int bits, bool safe) 
{
  bn_t result;
  BN_generate_prime_ex(result, bits, safe, NULL, NULL, NULL);
  return result;
}

bool bn_t::prime()
{
  return BN_is_prime_ex(*this, BN_prime_checks_for_size(get_bits_count()), tls_bn_ctx(), NULL) ? true : false;
}

bn_t bn_t::gcd(const bn_t& src1, const bn_t& src2)
{
  bn_t result;
  BN_gcd(result, src1, src2, tls_bn_ctx());
  return result;
}

bn_t bn_t::lcm(const bn_t& src1, const bn_t& src2)
{
  bn_t gcd_result;
  BN_gcd(gcd_result, src1, src2, tls_bn_ctx());
  return src1 * src2 / gcd_result;
}

void bn_t::set_modulo(const bn_t& mod)
{
  tls_set_modulo(mod);
}

bool bn_t::check_modulo()
{
  return tls_modulo()!=nullptr;
}

void bn_t::reset_modulo()
{
  tls_set_modulo(nullptr);
}

int bn_t::small_mod(int value) const
{
  return (int)BN_mod_word(*this, (BN_ULONG) value);
}

void bn_t::truncate(int bits)
{
  BN_mask_bits(*this, bits);
}

void montgomery_t::init(const bn_t& mod)
{
  BN_MONT_CTX_set(handle, mod, bn_t::tls_bn_ctx());
}

bn_t montgomery_t::to_mont(const bn_t& src) const
{
  bn_t result;
  int res = BN_to_montgomery(result, src, handle, bn_t::tls_bn_ctx());
  assert(res);
  return result;
}

bn_t montgomery_t::from_mont(const bn_t& src) const
{
  bn_t result;
  int res = BN_from_montgomery(result, src, handle, bn_t::tls_bn_ctx());
  assert(res);
  return result;
}

  
bn_t montgomery_t::mul(const bn_t& src1, const bn_t& src2) const
{
  bn_t result;
  int res = BN_mod_mul_montgomery(result, src1, src2, handle, bn_t::tls_bn_ctx());
  assert(res);
  return result;
}

bn_t montgomery_t::sqr(const bn_t& src) const
{
  bn_t result;
  int res = BN_mod_mul_montgomery(result, src, src, handle, bn_t::tls_bn_ctx());
  assert(res);
  return result;
}



}; //namespace crypto
