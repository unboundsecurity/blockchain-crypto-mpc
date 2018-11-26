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
#include "ub_cpuid.h"

#ifdef _WIN32

#if OPENSSL_VERSION_NUMBER >= 0x10100000
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#else
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#endif

#endif

namespace ub
{
template<> void scoped_ptr_t<RSA>                  ::free(RSA* ptr)                 { RSA_free(ptr);                      }
template<> void scoped_ptr_t<EC_KEY>               ::free(EC_KEY* ptr)              { EC_KEY_free(ptr);                   }
template<> void scoped_ptr_t<EVP_PKEY>             ::free(EVP_PKEY* ptr)            { EVP_PKEY_free(ptr);                 }
template<> void scoped_ptr_t<PKCS8_PRIV_KEY_INFO>  ::free(PKCS8_PRIV_KEY_INFO* ptr) { PKCS8_PRIV_KEY_INFO_free(ptr);      }
}

struct CRYPTO_dynlock_value
{
  ub::mutex_t mutex;
};

namespace crypto 
{

static unsigned long get_thread_id_for_openssl() 
{
  return (unsigned long) ub::thread_t::thread_id();
}

static ub::mutex_t *g_openssl_locks = NULL;

static void lock_callback_for_openssl(int mode, int type, const char *file, int line) 
{
  if (mode & CRYPTO_LOCK) g_openssl_locks[type].lock();
  else g_openssl_locks[type].unlock();
}

static struct CRYPTO_dynlock_value *dynamic_create_lock_callback_for_openssl(const char *file, int line)
{
  return new CRYPTO_dynlock_value;
}

static void dynamic_free_lock_callback_for_openssl(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
  delete l;
}

static void dynamic_lock_callback_for_openssl(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line) 
{
  if (mode & CRYPTO_LOCK) l->mutex.lock();
  else l->mutex.unlock();
}


#ifdef INTEL_X64
bool get_rd_rand(uint64_t& out)
{
  if (!ub::cpuid::has_rdrand()) return false;
  for (int i=0; i<15; i++)
  {
#ifdef _WIN32
    if (_rdrand64_step(&out)) return true;
#else
    unsigned char ok;
    asm volatile ("rdrand %0; setc %1"
        : "=r" (out), "=qm" (ok));
    if (ok) return true;
#endif
  }
  return false;
}

bool seed_rd_rand_entropy(int size)
{
  int count = (size+7) / 8;
  buf_t entropy(count*8);
  for (int i=0; i<size; i+=8)
  {
    uint64_t e;
    if (!get_rd_rand(e)) return false;
    *(uint64_t*)(entropy.data()+i) = e;
  }
  seed_random(entropy);
  return true;
}

#endif

static bool initialized = false;

initializer_t::initializer_t()
{

  has_id_callback = CRYPTO_get_id_callback() != NULL;
  has_locking_callback = CRYPTO_get_locking_callback() != NULL;
  has_dynamic_locking_callback = CRYPTO_get_dynlock_lock_callback() != NULL;

  OPENSSL_init();

  if (!has_id_callback) CRYPTO_set_id_callback(get_thread_id_for_openssl);

  if (!has_locking_callback)
  {
    g_openssl_locks = new ub::mutex_t[CRYPTO_num_locks()];
    CRYPTO_set_locking_callback(lock_callback_for_openssl);
  }

  if (!has_dynamic_locking_callback)
  {
    CRYPTO_set_dynlock_create_callback(dynamic_create_lock_callback_for_openssl);
    CRYPTO_set_dynlock_lock_callback(dynamic_lock_callback_for_openssl);
    CRYPTO_set_dynlock_destroy_callback(dynamic_free_lock_callback_for_openssl);
  }


  OPENSSL_add_all_algorithms_noconf();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  ERR_load_crypto_strings();

#ifdef INTEL_X64
  crypto::seed_rd_rand_entropy(32);
#endif

  initialized = true;
}

initializer_t::~initializer_t()
{
  if (!has_id_callback) CRYPTO_set_id_callback(NULL);
  if (!has_locking_callback) CRYPTO_set_locking_callback(NULL);
  if (!has_dynamic_locking_callback)
  {
    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);
  }
}


error_t error(const std::string& text)
{
  return ub::error(E_CRYPTO, ECATEGORY_CRYPTO, text);
}

error_t openssl_error(const std::string& text) { return openssl_error(E_CRYPTO, text); }


std::string openssl_get_last_error_string()
{
  char ssl_message[1024] = "";
  int err = ERR_get_error();
  ERR_error_string(err, ssl_message);
  return ssl_message;
}

error_t openssl_error(int rv, const std::string& text)
{
  int err = ERR_peek_error();
  std::string ssl_message = openssl_get_last_error_string();
  std::string message = text;
  if (message.empty()) message = "OPENSSL error: "; 

  return ub::error(rv, ECATEGORY_OPENSSL, message + "(" + strext::itoa(err) + ") " + ssl_message);
}


void seed_random(mem_t in)
{
  RAND_seed(in.data, in.size);
}

error_t gen_random(byte_ptr output, int size) 
{
  RAND_bytes(output, size);
  return 0;
}

error_t gen_random(mem_t out) 
{
  return gen_random(out.data, out.size);
}

bool gen_random_bool() 
{
  uint8_t temp;
  gen_random(&temp, 1);
  return (temp & 1) == 0;
}

buf_t gen_random(int size) 
{
  buf_t output(size);
  gen_random(output.data(), size);
  return output;
}

ub::bits_t gen_random_bits(int count)
{
  ub::bits_t out(count);
  gen_random((byte_ptr)out.get_data_buffer(), ub::bits_to_bytes(count));
  return out;
}

bool secure_equ(const_byte_ptr src1, const_byte_ptr src2, int size)
{
  byte_t x = 0;
  while (size--) x |= (*src1++) ^ (*src2++);
  return x==0;
}

bool secure_equ(mem_t src1, mem_t src2)
{
  if (src1.size!=src2.size) return false;
  return secure_equ(src1.data, src2.data, src1.size);
}

int evp_cipher_ctx_t::update(mem_t in, byte_ptr out)
{
  if (in.size==0) return 0;

  int out_size = 0;
  if (0 < EVP_CipherUpdate(ctx, out, &out_size, in.data, in.size)) return out_size;
  return -1;
}

int block_cipher_size(block_cipher_e alg)
{
  switch (alg)
  {
    case block_cipher_e::aes:  return AES_BLOCK_SIZE;
    case block_cipher_e::des3: return DES_BLOCK_SIZE;
  }
  assert(false);
  return 0;
}

static const EVP_CIPHER* cipher_aes_ecb(int key_size)
{
  switch (key_size)
  {
    case 16: return EVP_aes_128_ecb();
    case 24: return EVP_aes_192_ecb();
    case 32: return EVP_aes_256_ecb();
  }

  assert(false);
  return NULL;
}

static const EVP_CIPHER* cipher_aes_cbc(int key_size) 
{
  switch (key_size)
  {
    case 16: return EVP_aes_128_cbc();
    case 24: return EVP_aes_192_cbc();
    case 32: return EVP_aes_256_cbc();
  }
  assert(false);
  return NULL;
}


// ---------------------------- ECB ----------------------------

static const EVP_CIPHER* cipher_ecb(block_cipher_e alg, int key_size)
{
  switch (alg)
  {
    case block_cipher_e::aes:  return cipher_aes_ecb(key_size);
    //case block_cipher_e::des3: return cipher_des3_ecb();
  }
  assert(false);
  return NULL;
}

void ecb_t::encrypt_init(mem_t key) 
{
  int r = EVP_EncryptInit(ctx, cipher_ecb(alg, key.size), key.data, NULL);
  assert(0 < r);
  r = EVP_CIPHER_CTX_set_padding(ctx, 0);
  assert(0 < r);
}

void ecb_t::decrypt_init(mem_t key)
{
  int res = EVP_DecryptInit(ctx, cipher_ecb(alg, key.size), key.data, NULL);
  assert(0 < res);
  res = EVP_CIPHER_CTX_set_padding(ctx, 0);
  assert(0 < res);
}

buf_t ecb_t::encrypt(block_cipher_e type, mem_t key, mem_t in) // static
{
  buf_t out(in.size);
  ecb_t ecb(type);
  ecb.encrypt_init(key);
  ecb.update(in, out.data());
  return out;
}

buf_t ecb_t::decrypt(block_cipher_e type, mem_t key, mem_t in) // static
{
  buf_t out(in.size);
  ecb_t ecb(type);
  ecb.decrypt_init(key);
  ecb.update(in, out.data());
  return out;
}


// ------------------------- AES-CTR ---------------------------

static const EVP_CIPHER* cipher_aes_ctr(int key_size)
{
  switch (key_size)
  {
    case 16: return EVP_aes_128_ctr();
    case 24: return EVP_aes_192_ctr();
    case 32: return EVP_aes_256_ctr();
  }
  assert(false);
  return NULL;
}

void ctr_aes_t::init(mem_t key, const_byte_ptr iv) 
{
  int res = EVP_EncryptInit(ctx, cipher_aes_ctr(key.size), key.data, iv);
  assert(0 < res);
  res = EVP_CIPHER_CTX_set_padding(ctx, 0);
  assert(0 < res);
}

buf_t ctr_aes_t::encrypt(mem_t key, const_byte_ptr iv, mem_t in) 
{
  buf_t out(in.size);
  encrypt(key, iv, in, out.data());
  return out;
}

buf_t ctr_aes_t::decrypt(mem_t key, const_byte_ptr iv, mem_t in) 
{
  return encrypt(key, iv, in);
}

void ctr_aes_t::encrypt(mem_t key, const_byte_ptr iv, mem_t in, byte_ptr out) 
{
  ctr_aes_t ctr;
  ctr.init(key, iv);
  ctr.update(in, out);
}

void ctr_aes_t::decrypt(mem_t key, const_byte_ptr iv, mem_t in, byte_ptr out) 
{
  encrypt(key, iv, in, out);
}






} // namespace crypto
