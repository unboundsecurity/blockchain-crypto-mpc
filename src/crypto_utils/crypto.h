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
#include <openssl/objects.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>

#define DES_BLOCK_SIZE 8

#if OPENSSL_VERSION_NUMBER >= 0x10100000
#define OPENSSL_BN_PTR
#define OPENSSL_MD_PTR
#define OPENSSL_HMAC_PTR
#define OPENSSL_RSA_PTR
#endif

#include "ub_common.h"
#include "ub_error.h"
#include "ub_convert.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "libeay32.lib")
#pragma warning (disable: 4237) // export,import keywords
#endif

enum
{
  E_CRYPTO = ERRCODE(GERR_CRYPTO, 1)
};

extern unsigned small_primes[];
enum { small_primes_count = 10000 };

namespace crypto
{

class bn_t;
class ecc_point_t;

error_t error(const std::string& text);
error_t openssl_error(const std::string& text);
error_t openssl_error(int rv, const std::string& text);
std::string openssl_get_last_error_string();

class initializer_t
{
public:
  initializer_t();
  ~initializer_t();

private:
  bool has_id_callback, has_locking_callback, has_dynamic_locking_callback;
};

static ub::global_init_t<initializer_t> g_initializer;

#ifdef INTEL_X64
bool get_rd_rand(uint64_t& out);
bool seed_rd_rand_entropy(int size);
#endif

void seed_random(mem_t in);
error_t gen_random(byte_ptr output, int size);
error_t gen_random(mem_t out);
buf_t gen_random(int size);

ub::bits_t gen_random_bits(int count);
bool gen_random_bool();

template<typename T> T gen_random_int()
{
  T result;
  gen_random((byte_ptr)&result, sizeof(T));
  return result;
}

inline int rand()
{
	return int(gen_random_int<unsigned>() % RAND_MAX);
}

bool secure_equ(mem_t src1, mem_t src2);
bool secure_equ(const_byte_ptr src1, const_byte_ptr src2, int size);


enum class block_cipher_e
{
  none = 0,
  aes = 1, 
  des3 = 2, 
};

int block_cipher_size(block_cipher_e alg);

class evp_cipher_ctx_t
{
public:
  evp_cipher_ctx_t(block_cipher_e _alg) : alg(_alg), ctx(EVP_CIPHER_CTX_new()) {}
  ~evp_cipher_ctx_t() { EVP_CIPHER_CTX_free(ctx); }

  int update(mem_t in, byte_ptr out);

public:
  block_cipher_e alg;
  EVP_CIPHER_CTX* ctx;
};

class ecb_t : public evp_cipher_ctx_t
{
public:
  ecb_t(block_cipher_e alg) : evp_cipher_ctx_t(alg) {}

  void encrypt_init(mem_t key);
  void decrypt_init(mem_t key);


  static buf_t encrypt(block_cipher_e alg, mem_t key, mem_t in);
  static buf_t decrypt(block_cipher_e alg, mem_t key, mem_t in);
};


class ecb_aes_t  : public ecb_t 
{ 
public:  
  ecb_aes_t()  : ecb_t(block_cipher_e::aes)  {} 
  static buf_t encrypt(mem_t key, mem_t in) { return ecb_t::encrypt(block_cipher_e::aes, key, in); }
  static buf_t decrypt(mem_t key, mem_t in) { return ecb_t::decrypt(block_cipher_e::aes, key, in); }
};


class ctr_aes_t : public evp_cipher_ctx_t
{
public:
  ctr_aes_t() : evp_cipher_ctx_t(block_cipher_e::aes) {}
  void init(mem_t key, const_byte_ptr iv);
  void init(buf128_t key, buf128_t iv) { init(mem_t(key), const_byte_ptr(&iv)); }
  void init(buf256_t key, buf128_t iv) { init(mem_t(key), const_byte_ptr(&iv)); }
  static buf_t encrypt(mem_t key, const_byte_ptr iv, mem_t in);
  static buf_t decrypt(mem_t key, const_byte_ptr iv, mem_t in);
  static void encrypt(mem_t key, const_byte_ptr iv, mem_t in, byte_ptr out);
  static void decrypt(mem_t key, const_byte_ptr iv, mem_t in, byte_ptr out);
};


} // namespace crypto

#include "crypto_bn.h"
#include "crypto_ecc.h"
#include "crypto_hash.h"
#include "crypto_rsa.h"
#include "crypto_paillier.h"

using crypto::sha256_t;
using crypto::bn_t;
using crypto::ecc_point_t;
using crypto::ecurve_t;
using crypto::ecc_generator_point_t;

using crypto::ecp_25519_t;
using crypto::ecp_gen_25519_t;

