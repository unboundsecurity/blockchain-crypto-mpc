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
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "ub_common.h"

namespace crypto
{

enum { max_hash_size=EVP_MAX_MD_SIZE };

enum class hash_e
{ 
  md5 = NID_md5, 
  md2 = NID_md2, 
  md4 = NID_md4, 
  sha1 = NID_sha1, 
  sha256 = NID_sha256, 
  sha384 = NID_sha384, 
  sha512 = NID_sha512, 
  ripemd160 = NID_ripemd160,
  none = NID_undef,
};

class hash_alg_t
{
public:
  hash_e type;
  int size;
  int block_size;
  int state_size;
  mem_t oid;
  mem_t initial_state;
  const EVP_MD* md;

  bool valid() const { return type!=hash_e::none; }

  static const hash_alg_t& get(hash_e type);
};

class bn_t;
class ecc_point_t;
class ecc_generator_point_t;
class ecp_25519_t;
class ecp_gen_25519_t;

template<class T> T& update_state(T& state, const null_data_t& v)              { return state; }
template<class T> T& update_state(T& state, mem_t v)                           { return state.update(v.data, v.size); }
template<class T> T& update_state(T& state, bool v)                            { return update_state(state, byte_t(v ? 1 : 0)); }
template<class T> T& update_state(T& state, byte_t v)                          { return state.update(&v, 1); }
template<class T> T& update_state(T& state, uint16_t v)                        { byte_t temp[2]; ub::be_set_2(temp, v); return state.update(temp, 2); }
template<class T> T& update_state(T& state, int16_t v)                         { return update_state(state, uint16_t(v)); }
template<class T> T& update_state(T& state, uint32_t v)                        { byte_t temp[4]; ub::be_set_4(temp, v); return state.update(temp, 4); }
template<class T> T& update_state(T& state, int32_t v)                         { return update_state(state, uint32_t(v)); }
template<class T> T& update_state(T& state, uint64_t v)                        { byte_t temp[8]; ub::be_set_8(temp, v); return state.update(temp, 8); }
template<class T> T& update_state(T& state, int64_t v)                         { return update_state(state, uint64_t(v)); }
template<class T> T& update_state(T& state, const std::string& v)              { return update_state(state, strext::mem(v)); }
template<class T> T& update_state(T& state, const_char_ptr v)                  { if (v) state.update(const_byte_ptr(v), int(strlen(v))); return state; }
template<class T> T& update_state(T& state, const bn_t& v)                     { return update_state(state, v.to_bin()); }
template<class T> T& update_state(T& state, const ecc_point_t& v)              { return update_state(state, v.to_compressed_oct()); }
template<class T> T& update_state(T& state, const ecc_generator_point_t& v)    { return update_state(state, v.to_compressed_oct()); }
template<class T> T& update_state(T& state, const ecp_25519_t& v)              { return update_state(state, v.encode()); }
template<class T> T& update_state(T& state, const ecp_gen_25519_t& v)          { return update_state(state, v.encode()); }
template<class T, typename V> T& update_state(T& state, const V& v)            { return update_state(state, mem_t(v)); }

#define TEMPLATE_PARAMS \
  typename T1, \
  typename T2=const null_data_t, \
  typename T3=const null_data_t, \
  typename T4=const null_data_t, \
  typename T5=const null_data_t, \
  typename T6=const null_data_t, \
  typename T7=const null_data_t, \
  typename T8=const null_data_t, \
  typename T9=const null_data_t, \
  typename T10=const null_data_t, \
  typename T11=const null_data_t, \
  typename T12=const null_data_t, \
  typename T13=const null_data_t, \
  typename T14=const null_data_t, \
  typename T15=const null_data_t
 
#define DEFAULT_PARAMS \
  const T1& v1, \
  const T2& v2=*(const null_data_t*)(nullptr), \
  const T3& v3=*(const null_data_t*)(nullptr), \
  const T4& v4=*(const null_data_t*)(nullptr), \
  const T5& v5=*(const null_data_t*)(nullptr), \
  const T6& v6=*(const null_data_t*)(nullptr), \
  const T7& v7=*(const null_data_t*)(nullptr), \
  const T8& v8=*(const null_data_t*)(nullptr), \
  const T9& v9=*(const null_data_t*)(nullptr), \
  const T10& v10=*(const null_data_t*)(nullptr), \
  const T11& v11=*(const null_data_t*)(nullptr), \
  const T12& v12=*(const null_data_t*)(nullptr), \
  const T13& v13=*(const null_data_t*)(nullptr), \
  const T14& v14=*(const null_data_t*)(nullptr), \
  const T15& v15=*(const null_data_t*)(nullptr)

class hash_t
{
public:
  hash_t(hash_e type) : alg(hash_alg_t::get(type)) 
  { 
#ifdef OPENSSL_MD_PTR
    ctx_ptr = ::EVP_MD_CTX_new(); 
#else
    ::EVP_MD_CTX_init(&ctx); 
#endif
  }
  ~hash_t() { free(); }

  void free() 
  { 
#ifdef OPENSSL_MD_PTR
    if (ctx_ptr) ::EVP_MD_CTX_free(ctx_ptr); 
    ctx_ptr = nullptr;
#else
    ::EVP_MD_CTX_cleanup(&ctx); 
#endif
  }

  hash_t& init();
  hash_t& update(const_byte_ptr ptr, int size);
  void final(byte_ptr out);
  buf_t final();

  template<typename T> hash_t& update (const T& v) { return update_state(*this, v); }

private:
  const hash_alg_t& alg;
#ifdef OPENSSL_MD_PTR
  EVP_MD_CTX* ctx_ptr;
#else
  EVP_MD_CTX ctx;
#endif
};

class sha256_t;

template<hash_e hash_type> class hash_template_t
{
public:
  hash_template_t() : state(hash_type) { state.init(); }

  template<typename T> hash_template_t& update (const T& v) { state.update(v); return *this; }

  template<TEMPLATE_PARAMS> hash_template_t (DEFAULT_PARAMS) : state(hash_type)
  {
    state.init();
    update(v1);
    update(v2);
    update(v3);
    update(v4);
    update(v5);
    update(v6);
    update(v7);
    update(v8);
    update(v9);
    update(v10);
    update(v11);
    update(v12);
    update(v13);
    update(v14);
    update(v15);
  }

  template<TEMPLATE_PARAMS> static buf_t hash (DEFAULT_PARAMS)
  {
    return hash_template_t(v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15).final();
  }

  void final(byte_ptr out) { state.final(out); }
  buf_t final()  { return state.final(); }

protected:
  hash_t state;
};

class sha256_t : public hash_template_t<hash_e::sha256>
{
public:
  sha256_t() : hash_template_t<hash_e::sha256>() {}

  template<TEMPLATE_PARAMS> sha256_t (DEFAULT_PARAMS) : hash_template_t<hash_e::sha256>(v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15)
  { 
  }
  
  template<typename T> sha256_t& update (const T& v) { state.update(v); return *this; }

  void final(byte_ptr out) { state.final(out); }
  buf256_t final()  { buf256_t out; state.final(out); return out; }
  
  template<TEMPLATE_PARAMS> static buf256_t hash (DEFAULT_PARAMS)
  {
    return sha256_t(v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15).final();
  }
};


typedef hash_template_t<hash_e::md5> md5_t;
typedef hash_template_t<hash_e::sha1> sha1_t;
//typedef hash_template_t<hash_e::sha256> sha256_t;
typedef hash_template_t<hash_e::sha384> sha384_t;
typedef hash_template_t<hash_e::sha512> sha512_t;
typedef hash_template_t<hash_e::ripemd160> ripemd160_t;


uint64_t sha256_truncated_uint64(mem_t mem);

class hash_state_t
{
public:
  hash_state_t(hash_e type) : alg(hash_alg_t::get(type)) { init(); }
  ~hash_state_t();

  void init();
  void update(mem_t in);
  void final(byte_ptr out);
  buf_t final();

  void get_state(byte_ptr state) const;
  buf_t get_state() const;
  void set_state(const_byte_ptr state, int full_size);

private:
  const hash_alg_t& alg;
  byte_t buffer[128];
  int buf_size;
  int full_size;
  union { uint32_t h32[8]; uint64_t h64[8]; };

  void sha512_init();

  void transform();
  void sha512_transform();

  void sha512_get_state(byte_ptr state) const;

  void sha512_set_state(const_byte_ptr state);
};


class hmac_t
{
public:
  hmac_t(hash_e type) : alg(hash_alg_t::get(type)) 
  { 
#ifdef OPENSSL_HMAC_PTR
    ctx_ptr = HMAC_CTX_new();
#else
    HMAC_CTX_init(&ctx); 
#endif
  }
  ~hmac_t() 
  { 
#ifdef OPENSSL_HMAC_PTR
    if (ctx_ptr) HMAC_CTX_free(ctx_ptr);
#else
    HMAC_CTX_cleanup(&ctx); 
#endif
  }

  hmac_t& init(mem_t key);
  hmac_t& update(const byte_ptr ptr, int size);

  template<typename T> hmac_t& update (const T& v) { return update_state(*this, v); }

  void final(byte_ptr out);
  buf_t final();

private:
  const hash_alg_t& alg;
#ifdef OPENSSL_HMAC_PTR
  HMAC_CTX* ctx_ptr;
#else
  HMAC_CTX ctx;
#endif
};

template<hash_e type> class hmac_template_t
{
public:
  hmac_template_t(mem_t key) : state(type) { state.init(key); }

  template<typename T> hmac_template_t& update (const T& v) { state.update(v); return *this; }

  template<TEMPLATE_PARAMS> buf_t calculate (DEFAULT_PARAMS)
  {
    update(v1);
    update(v2);
    update(v3);
    update(v4);
    update(v5);
    update(v6);
    update(v7);
    update(v8);
    update(v9);
    update(v10);
    update(v11);
    update(v12);
    update(v13);
    update(v14);
    update(v15);
    return final();
  }

  void final(byte_ptr out) { state.final(out); }
  buf_t final() { return state.final(); }

protected:
  hmac_t state;
};

typedef hmac_template_t<hash_e::md5>    hmac_md5_t;
typedef hmac_template_t<hash_e::sha1>   hmac_sha1_t;
//typedef hmac_template_t<hash_e::sha256> hmac_sha256_t;
typedef hmac_template_t<hash_e::sha384> hmac_sha384_t;
typedef hmac_template_t<hash_e::sha512> hmac_sha512_t;

class hmac_sha256_t : public hmac_template_t<hash_e::sha256>
{
public:
  hmac_sha256_t(mem_t key) : hmac_template_t<hash_e::sha256>(key) {  }

  template<typename T> hmac_sha256_t& update (const T& v) { state.update(v); return *this; }
  //template<typename T> hmac_sha256_t& update (T v)        { state.update(v); return *this; }

  template<TEMPLATE_PARAMS> buf256_t calculate (DEFAULT_PARAMS)
  {
    update(v1);
    update(v2);
    update(v3);
    update(v4);
    update(v5);
    update(v6);
    update(v7);
    update(v8);
    update(v9);
    update(v10);
    update(v11);
    update(v12);
    update(v13);
    update(v14);
    update(v15);
    return final();
  }

  void final(byte_ptr out) { state.final(out); }
  buf256_t final() { buf256_t out; final(byte_ptr(out)); return out; }

};

inline buf256_t random_oracle_hash(mem_t input)
{
  static const byte_t random_oracle_key[16] = {0xf4, 0x91, 0xf2, 0x73, 0x2b, 0x8d, 0x40, 0xe7, 0x81, 0x2b, 0x53, 0x5c, 0x6e, 0xa5, 0xbb, 0xc4};
  return hmac_sha256_t(mem_t(random_oracle_key, 16)).calculate(input);
}

} //namespace crypto
