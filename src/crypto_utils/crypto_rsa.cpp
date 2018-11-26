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

  
rsa_key_t::data_t rsa_key_t::get(const RSA* rsa)
{
  data_t data;

#ifdef OPENSSL_RSA_PTR
  RSA_get0_key(rsa, (const BIGNUM**)&data.n, (const BIGNUM**)&data.e, (const BIGNUM**)&data.d);
  RSA_get0_factors(rsa, (const BIGNUM**)&data.p, (const BIGNUM**)&data.q);
  RSA_get0_crt_params(rsa, (const BIGNUM**)&data.dp, (const BIGNUM**)&data.dq, (const BIGNUM**)&data.qinv);
#else
  data.n = rsa->n;
  data.e = rsa->e;
  data.d = rsa->d;
  data.p = rsa->p;
  data.q = rsa->q;
  data.dp = rsa->dmp1;
  data.dq = rsa->dmq1;
  data.qinv = rsa->iqmp;
#endif

  return data;
}

void rsa_key_t::set(RSA* rsa, const BIGNUM *n, const BIGNUM *e)
{
  assert(n && e);
  n = BN_dup(n);
  e = BN_dup(e);
#ifdef OPENSSL_RSA_PTR
  RSA_set0_key(rsa, (BIGNUM*)n, (BIGNUM*)e, nullptr);
#else
  BN_free(rsa->n); rsa->n = (BIGNUM*)n; 
  BN_free(rsa->e); rsa->e = (BIGNUM*)e; 
#endif
}

void rsa_key_t::set(RSA* rsa, const BIGNUM *n, const BIGNUM *e, const BIGNUM *d)
{
  assert(n && e && d);
  n = BN_dup(n);
  e = BN_dup(e);
  d = BN_dup(d);

#ifdef OPENSSL_RSA_PTR
  RSA_set0_key(rsa, (BIGNUM*)n, (BIGNUM*)e, (BIGNUM*)d);
#else
  BN_free(rsa->n); rsa->n = (BIGNUM*)n; 
  BN_free(rsa->e); rsa->e = (BIGNUM*)e; 
  BN_free(rsa->d); rsa->d = (BIGNUM*)d; 
#endif
}

void rsa_key_t::set(RSA* rsa, const BIGNUM* n, const BIGNUM* e, const BIGNUM* d, const BIGNUM* p, const BIGNUM* q, const BIGNUM* dp, const BIGNUM* dq, const BIGNUM* qinv)
{
  assert(n && e && d && p && q && dp && dq && qinv);

  n = BN_dup(n);
  e = BN_dup(e);
  d = BN_dup(d);
  p = BN_dup(p);
  q = BN_dup(q);
  dp = BN_dup(dp);
  dq = BN_dup(dq);
  qinv = BN_dup(qinv);

#ifdef OPENSSL_RSA_PTR
  RSA_set0_key(rsa, (BIGNUM*)n, (BIGNUM*)e, (BIGNUM*)d);
  RSA_set0_factors(rsa, (BIGNUM*)p, (BIGNUM*)q);
  RSA_set0_crt_params(rsa, (BIGNUM*)dp, (BIGNUM*)dq, (BIGNUM*)qinv);
#else
  BN_free(rsa->n); rsa->n = (BIGNUM*)n; 
  BN_free(rsa->e); rsa->e = (BIGNUM*)e; 
  BN_free(rsa->d); rsa->d = (BIGNUM*)d; 
  BN_free(rsa->p); rsa->p = (BIGNUM*)p; 
  BN_free(rsa->q); rsa->q = (BIGNUM*)q; 
  BN_free(rsa->dmp1); rsa->dmp1 = (BIGNUM*)dp; 
  BN_free(rsa->dmq1); rsa->dmq1 = (BIGNUM*)dq; 
  BN_free(rsa->iqmp); rsa->iqmp = (BIGNUM*)qinv; 
#endif
}


static void_ptr* find_ptr(void_ptr buffer, void_ptr pointer)
{
  byte_ptr buf = byte_ptr(buffer);
  for (;;)
  {
    void_ptr* b = (void_ptr*)buf++;
    if (pointer == *b) return b;
  }
  return nullptr;
}

void rsa_key_t::set_paillier(const BIGNUM *n, const BIGNUM *p, const BIGNUM *q, const BIGNUM *dp, const BIGNUM *dq, const BIGNUM *qinv)
{
  assert(n && p && q && dp && dq && qinv);

  n = BN_dup(n);
  p = BN_dup(p);
  q = BN_dup(q);
  dp = BN_dup(dp);
  dq = BN_dup(dq);
  qinv = BN_dup(qinv);

#ifdef OPENSSL_RSA_PTR
  BIGNUM* e = BN_new();
  RSA_set0_key(ptr, (BIGNUM*)n, (BIGNUM*)e, nullptr);
  RSA_set0_factors(ptr, (BIGNUM*)p, (BIGNUM*)q);
  RSA_set0_crt_params(ptr, (BIGNUM*)dp, (BIGNUM*)dq, (BIGNUM*)qinv);
  void_ptr* ref = find_ptr(ptr, e);
  *ref = NULL;
  BN_free(e);
#else
  BN_free(ptr->e); ptr->e = NULL;
  BN_free(ptr->d); ptr->d = NULL;

  BN_free(ptr->n); ptr->n = (BIGNUM*)n; 
  BN_free(ptr->p); ptr->p = (BIGNUM*)p; 
  BN_free(ptr->q); ptr->q = (BIGNUM*)q; 
  BN_free(ptr->dmp1); ptr->dmp1 = (BIGNUM*)dp; 
  BN_free(ptr->dmq1); ptr->dmq1 = (BIGNUM*)dq; 
  BN_free(ptr->iqmp); ptr->iqmp = (BIGNUM*)qinv; 
#endif
}

void rsa_key_t::set(RSA* rsa, const data_t& data)
{
  if (data.p) set(rsa, data.n, data.e, data.d, data.p, data.q, data.dp, data.dq, data.qinv);
  else if (data.d) set(rsa, data.n, data.e, data.d);
  else set(rsa, data.n, data.e);
}

int rsa_key_t::size() const 
{ 
  const BIGNUM* n = nullptr;
#ifdef OPENSSL_RSA_PTR
  RSA_get0_key(ptr, (const BIGNUM**)&n, nullptr, nullptr);
#else
  n = ptr->n;
#endif
  return n ? ::RSA_size(ptr) : 0; 
}

bool rsa_key_t::has_prv() const 
{ 
  data_t data = get();
  return data.d || data.p;
}


void rsa_key_t::free()
{
  if (ptr) RSA_free(ptr);
  ptr = nullptr;
}

rsa_key_t::rsa_key_t(const rsa_key_t& src)
{
  ptr = src.ptr;
  if (ptr) RSA_up_ref(ptr);
}

rsa_key_t::rsa_key_t(rsa_key_t&& src) //move assignment
{
  ptr = src.ptr;
  src.ptr = nullptr;
}

rsa_key_t& rsa_key_t::operator = (const rsa_key_t& src)
{
  if (this!=&src)
  {
    free();
    ptr = src.ptr;
    if (ptr) RSA_up_ref(ptr);
  }
  return *this;
}

rsa_key_t& rsa_key_t::operator = (rsa_key_t&& src)  //move assignment
{
  if (this!=&src)
  {
    free();
    ptr = src.ptr;
    src.ptr = nullptr;
  }
  return *this;
}

rsa_key_t rsa_key_t::copy(RSA* ptr) //static
{
  rsa_key_t result;
  result.ptr = ptr;
  if (ptr) RSA_up_ref(ptr);
  return result;
}

RSA* rsa_key_t::copy() const
{
  if (ptr) RSA_up_ref(ptr);
  return ptr;
}

void rsa_key_t::create()
{
  free();
  ptr = RSA_new();
}


void rsa_key_t::generate(int bits, int e)
{
  if (e==0) e=65537;
  bn_t pub_exp(e);
  generate(bits, pub_exp);
}

void rsa_key_t::generate(int bits, const bn_t& e)
{
  create();
  int res = RSA_generate_key_ex(ptr, bits, (BIGNUM*)(const BIGNUM*)e, nullptr);
  assert(1==res);
}

bool rsa_key_t::encrypt_raw(const_byte_ptr in, byte_ptr out) const
{
  int n_size = size();
  if (0<RSA_public_encrypt(n_size, in, out, ptr, RSA_NO_PADDING)) return true;
  openssl_error("RSA encrypt RAW error");
  return false; 
}

bool rsa_key_t::decrypt_raw(const_byte_ptr in, byte_ptr out) const
{
  int n_size = size();
  if (0<RSA_private_decrypt(n_size, in, out, ptr, RSA_NO_PADDING)) return true;
  openssl_error("RSA decrypt RAW error");
  return false;
}

bool rsa_key_t::verify_pkcs1(mem_t in, hash_e hash_alg, const_byte_ptr signature) const
{
  int n_size = size();
  if (hash_alg!=hash_e::none)  
  {
    if (1==RSA_verify(int(hash_alg), in.data, in.size, signature, n_size, ptr)) return true;
    openssl_error("RSA verify PKCS1 error in.size=" + strext::itoa(in.size) + " hash_alg=" + strext::itoa(int(hash_alg)));
    return false;
  }

  buf_t temp(n_size);
  int temp_size = RSA_public_decrypt(n_size, signature, temp.data(), ptr, RSA_PKCS1_PADDING);
  if (temp_size<0)
  {
    openssl_error("RSA verify PKCS1 data size mismatch, data-size="+strext::itoa(in.size));
    return false;
  }
  if (temp_size!=in.size)
  {
    crypto::error("RSA verify PKCS1 data size mismatch, data-size="+strext::itoa(in.size)+", unpad-size="+strext::itoa(temp_size));
    return false;
  }
  if (!secure_equ(temp.data(), in.data, in.size))
  {
    crypto::error("RSA verify PKCS1 error"+strext::itoa(int(hash_alg)));
    return false;
  }

  return true;
}

bool rsa_key_t::sign_pkcs1(mem_t in, hash_e hash_alg, byte_ptr signature) const
{
  unsigned int signature_size = size();
  if (hash_alg==hash_e::none) 
  {
    if (0<RSA_private_encrypt(in.size, in.data, signature, ptr, RSA_PKCS1_PADDING)) return true;
    openssl_error("RSA sign PKCS1 error");
    return false;
  }
  if (0<RSA_sign(int(hash_alg), in.data, in.size, signature, &signature_size, ptr)) return true;
  openssl_error("RSA sign PKCS1 error"+strext::itoa(int(hash_alg)));
  return false;
}

buf_t rsa_key_t::sign_pkcs1(mem_t data, hash_e hash_alg) const
{
  buf_t out(size());
  if (!sign_pkcs1(data, hash_alg, out.data())) out.free();
  return out;
}

bool rsa_key_t::encrypt_pkcs1(mem_t in, byte_ptr out) const
{
  if (0<RSA_public_encrypt(in.size, in.data, out, ptr, RSA_PKCS1_PADDING)) return true;
  openssl_error("RSA encrypt PKCS1 error");
  return false;
}

buf_t rsa_key_t::encrypt_pkcs1(mem_t in) const
{
  buf_t out(size());
  encrypt_pkcs1(in, out.data());
  return out;
}

int rsa_key_t::decrypt_pkcs1(mem_t in, byte_ptr out) const
{
  buf_t buf;
  if (!out) out = buf.resize(in.size);
  int res = RSA_private_decrypt(in.size, in.data, out, ptr, RSA_PKCS1_PADDING);
  if (res < 0)
  {
    openssl_error("RSA decrypt PKCS1 error, data-size=" + strext::itoa(in.size));
  }
  return res;
}


bool rsa_key_t::decrypt_pkcs1(mem_t in, buf_t& out) const
{
  int out_size = decrypt_pkcs1(in, out.resize(in.size));
  if (out_size < 0)
  {
    out.free();
    return false;
  }
  out.resize(out_size, true);
  return true;
}

static buf_t prepend_oid(hash_e hash_alg, mem_t data)
{
  mem_t oid = hash_alg_t::get(hash_alg).oid;
  buf_t out(oid.size + data.size);
  memmove(out.data(), oid.data, oid.size);
  memmove(out.data()+oid.size, data.data, data.size);
  return out;
}

bool rsa_key_t::pad_for_sign_pkcs1(int bits, mem_t data, hash_e hash_alg, byte_ptr out)
{
  int out_size = ub::bits_to_bytes(bits);
  if (hash_alg==hash_e::none) 
  {
    if (0<RSA_padding_add_PKCS1_type_1(out, out_size, data.data, data.size)) return true;
    openssl_error("RSA_padding_add_PKCS1_type_1 error, bits="+strext::itoa(bits)+", data-size="+strext::itoa(data.size));
    return false;
  }

  buf_t temp = prepend_oid(hash_alg, data);
  if (0<RSA_padding_add_PKCS1_type_1(out, out_size, temp.data(), temp.size())) return true;
  openssl_error("RSA_padding_add_PKCS1_type_1 error, bits="+strext::itoa(bits)+", hash-alg="+strext::itoa(int(hash_alg))+", data-size="+strext::itoa(data.size));
  return false;
}

buf_t rsa_key_t::pad_for_sign_pkcs1(int bits, mem_t data, hash_e hash_alg)
{
  int out_size = ub::bits_to_bytes(bits);
  buf_t out(out_size);
  if (!pad_for_sign_pkcs1(bits, data, hash_alg, out.data())) out.free();
  return out;
}

bool rsa_key_t::unpad_and_verify_pkcs1(mem_t data, hash_e hash_alg, mem_t test)
{
  int rv=0; 
  int key_size = data.size;
  buf_t temp(key_size);
  int temp_size = RSA_padding_check_PKCS1_type_1(temp.data(), data.size, data.data, key_size, key_size);
  if (temp_size<0) 
  {
    rv = openssl_error("RSA verify unpad error");
    return false;
  }
  if (hash_alg==hash_e::none)
  {
    if (temp_size!=test.size)
    {
      rv = crypto::error("RSA signature size mismatch, sig-size=" + strext::itoa(test.size) + ", unpad-size="  + strext::itoa(temp_size));
      return false;
    }

    if (!secure_equ(temp.data(), test.data, test.size))
    {
      rv = crypto::error("RSA verify fail");
      return false;
    }
  }
  else
  {
    mem_t oid = hash_alg_t::get(hash_alg).oid;
    if (temp_size != oid.size + test.size) 
    {
      rv = crypto::error("RSA signature hash OID size mismatch, oid-size=" + strext::itoa(oid.size));
      return false;
    }

    if (!secure_equ(temp.data(), oid.data, oid.size))
    {
      rv = crypto::error("RSA signature hash OID mismatch");
      return false;
    }

    if (!secure_equ(temp.data()+oid.size, test.data, test.size))
    {
      rv = crypto::error("RSA verify fail, hash-alg=" + strext::itoa(int(hash_alg)));
      return false;
    }

  }
  return true;
}

bool rsa_key_t::pad_for_encrypt_pkcs1(int bits, mem_t in, byte_ptr out)
{
  int out_size = ub::bits_to_bytes(bits);
  if (0<RSA_padding_add_PKCS1_type_2(out, out_size, in.data, in.size)) return true;
  openssl_error("RSA encrypt pad error, bits=" + strext::itoa(bits)+ ", data-size=" + strext::itoa(in.size));
  return false;
}

buf_t rsa_key_t::pad_for_encrypt_pkcs1(int bits, mem_t in)
{
  int out_size = ub::bits_to_bytes(bits);
  buf_t out(out_size);
  if (!pad_for_encrypt_pkcs1(bits, in, out.data())) out.free();
  return out;
}

int rsa_key_t::unpad_decrypted_pkcs1(mem_t in, byte_ptr out)
{
  int key_size = in.size;
  buf_t temp;
  if (!out) out = temp.resize(key_size);
  if (key_size<=0) return -1;
  if (in[0]!=0) 
  {
    crypto::error("RSA decrypt unpad error, key-size=" + strext::itoa(key_size) + ", data-size=" + strext::itoa(in.size));
    return -1;
  }

  int res = RSA_padding_check_PKCS1_type_2(out, key_size, in.data+1, key_size-1, key_size);
  if (res<0) openssl_error("RSA decrypt unpad error, key-size=" + strext::itoa(key_size) + ", data-size=" + strext::itoa(in.size));
  return res;
}

bool rsa_key_t::unpad_decrypted_pkcs1(mem_t in, buf_t& out)
{
  int out_size = unpad_decrypted_pkcs1(in, nullptr);
  if (out_size<0) return false;

  unpad_decrypted_pkcs1(in, out.resize(out_size));
  return true;
}

enum 
{ 
  part_e    = 1<<0, 
  part_n    = 1<<1, 
  part_d    = 1<<2, 
  part_p    = 1<<3, 
  part_q    = 1<<4, 
  part_dp   = 1<<5, 
  part_dq   = 1<<6, 
  part_qinv = 1<<7, 
};

void rsa_key_t::convert(ub::converter_t& converter)
{
  uint8_t parts = 0;
  bn_t e, n, d, p, q, dp, dq, qinv;

  if (converter.is_write())
  {
    data_t data = get();

    if (data.e)    { parts |= part_e;      e    = bn_t(data.e);    }
    if (data.n)    { parts |= part_n;      n    = bn_t(data.n);    }
    if (data.d)    { parts |= part_d;      d    = bn_t(data.d);    }
    if (data.p)    { parts |= part_p;      p    = bn_t(data.p);    }
    if (data.q)    { parts |= part_q;      q    = bn_t(data.q);    }
    if (data.dp)   { parts |= part_dp;     dp   = bn_t(data.dp);   }
    if (data.dq)   { parts |= part_dq;     dq   = bn_t(data.dq);   }
    if (data.qinv) { parts |= part_qinv;   qinv = bn_t(data.qinv); }
  }

  version_t header(converter);
  converter.convert(parts);

  if (converter.is_error()) return;
  if (parts & part_e)    converter.convert(e);
  if (parts & part_n)    converter.convert(n);
  if (parts & part_d)    converter.convert(d);
  if (parts & part_p)    converter.convert(p);
  if (parts & part_q)    converter.convert(q);
  if (parts & part_dp)   converter.convert(dp);
  if (parts & part_dq)   converter.convert(dq);
  if (parts & part_qinv) converter.convert(qinv);

  if (!converter.is_write() && !converter.is_error())
  {
    create();
    switch (parts)
    {
      case 0: break;
      case part_e | part_n:                                                             set(n, e); break;
      case part_e | part_n | part_d:                                                    set(n, e, d); break;
      case part_n | part_p | part_q | part_dp | part_dq | part_qinv:                    set_paillier(n, p, q, dp, dq, qinv); break;
      case part_e | part_n | part_d | part_p | part_q | part_dp | part_dq | part_qinv:  set(n, e, d, p, q, dp, dq, qinv); break;
      default: converter.set_error(); free(); return;
    }
  }
}

buf_t rsa_key_t::export_pkcs8_prv() const
{
  ub::scoped_ptr_t<EVP_PKEY> evp = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(evp, ptr);

  ub::scoped_ptr_t<PKCS8_PRIV_KEY_INFO> pkcs8 = EVP_PKEY2PKCS8(evp);
  int size = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, NULL);
  buf_t result(size);
  byte_ptr dst = result.data();
  i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &dst);
  return result;
}

rsa_key_t rsa_key_t::import_pkcs8_prv(mem_t in)
{
  rsa_key_t rsa;

  const_byte_ptr src = in.data;
  ub::scoped_ptr_t<PKCS8_PRIV_KEY_INFO> pkcs8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &src, in.size);
  if (!pkcs8) 
  {
    openssl_error("d2i_PKCS8_PRIV_KEY_INFO error, data-size="+strext::itoa(in.size));
    return rsa;
  }

  ub::scoped_ptr_t<EVP_PKEY> evp = EVP_PKCS82PKEY(pkcs8);
  if (!evp) 
  {
    openssl_error("EVP_PKCS82PKEY error");
    return rsa;
  }

  rsa.ptr = EVP_PKEY_get1_RSA(evp);
  if (!rsa.ptr)
  {
    openssl_error("EVP_PKEY_get1_RSA error");
  }

  return rsa;
}

buf_t rsa_key_t::export_pub_key_info() const
{
  buf_t out;
  int out_size = i2d_RSA_PUBKEY(ptr, nullptr);
  if (out_size>0) 
  {
    byte_ptr out_ptr = out.resize(out_size);
    i2d_RSA_PUBKEY(ptr, &out_ptr);
  }
  else
  {
    openssl_error("i2d_RSA_PUBKEY error");
  }
  return out;
}

rsa_key_t rsa_key_t::import_pub_key_info(mem_t in) // static
{
  rsa_key_t key;
  const_byte_ptr in_ptr = in.data;
  key.ptr = d2i_RSA_PUBKEY(nullptr, &in_ptr, in.size);
  if (!key.ptr) openssl_error("d2i_RSA_PUBKEY error, data-size="+strext::itoa(in.size));
  return key;
}

}