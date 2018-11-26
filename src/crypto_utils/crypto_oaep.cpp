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
#include "ub_common.h"
#include "crypto.h"

/*
 * Written by Ulf Moeller. This software is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.
 */

/* EME-OAEP as defined in RFC 2437 (PKCS #1 v2.0) */

/*
 * See Victor Shoup, "OAEP reconsidered," Nov. 2000, <URL:
 * http://www.shoup.net/papers/oaep.ps.Z> for problems with the security
 * proof for the original OAEP scheme, which EME-OAEP is based on. A new
 * proof can be found in E. Fujisaki, T. Okamoto, D. Pointcheval, J. Stern,
 * "RSA-OEAP is Still Alive!", Dec. 2000, <URL:
 * http://eprint.iacr.org/2000/061/>. The new proof has stronger requirements
 * for the underlying permutation: "partial-one-wayness" instead of
 * one-wayness.  For the RSA function, this is an equivalent notion.
 */

namespace crypto {

static inline unsigned int constant_time_select(unsigned int mask,
                                                unsigned int a,
                                                unsigned int b)
{
    return (mask & a) | (~mask & b);
}

static inline int constant_time_select_int(unsigned int mask, int a, int b)
{
    return (int)(constant_time_select(mask, (unsigned)(a), (unsigned)(b)));
}

static inline unsigned int constant_time_msb(unsigned int a)
{
    return 0 - (a >> (sizeof(a) * 8 - 1));
}

static inline unsigned int constant_time_is_zero(unsigned int a)
{
    return constant_time_msb(~a & (a - 1));
}

static inline unsigned int constant_time_eq(unsigned int a, unsigned int b)
{
    return constant_time_is_zero(a ^ b);
}

#ifndef RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1
#define RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1 0
#define RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1 0
#endif

int PKCS1_MGF1_ex(unsigned char *mask, long len,
               const unsigned char *seed, long seedlen, const EVP_MD *dgst)
{
    long i, outlen = 0;
    unsigned char cnt[4];

#ifdef OPENSSL_MD_PTR
    EVP_MD_CTX* c_ptr = EVP_MD_CTX_new();
#else
    EVP_MD_CTX c;
    EVP_MD_CTX* c_ptr = &c;
    EVP_MD_CTX_init(c_ptr);
#endif
    unsigned char md[EVP_MAX_MD_SIZE];
    int mdlen;
    int rv = -1;

    mdlen = EVP_MD_size(dgst);
    if (mdlen < 0)
        goto err;
    for (i = 0; outlen < len; i++) {
        cnt[0] = (unsigned char)((i >> 24) & 255);
        cnt[1] = (unsigned char)((i >> 16) & 255);
        cnt[2] = (unsigned char)((i >> 8)) & 255;
        cnt[3] = (unsigned char)(i & 255);
        if (!EVP_DigestInit_ex(c_ptr, dgst, NULL)
            || !EVP_DigestUpdate(c_ptr, seed, seedlen)
            || !EVP_DigestUpdate(c_ptr, cnt, 4))
            goto err;
        if (outlen + mdlen <= len) {
            if (!EVP_DigestFinal_ex(c_ptr, mask + outlen, NULL))
                goto err;
            outlen += mdlen;
        } else {
            if (!EVP_DigestFinal_ex(c_ptr, md, NULL))
                goto err;
            memcpy(mask + outlen, md, len - outlen);
            outlen = len;
        }
    }
    rv = 0;
  err:
#ifdef OPENSSL_MD_PTR
    EVP_MD_CTX_free(c_ptr);
#else
    EVP_MD_CTX_cleanup(c_ptr);
#endif
    return rv;
}

int rsa_key_t::RSA_padding_add_PKCS1_OAEP_ex(unsigned char *to, int tlen,
                                    const unsigned char *from, int flen,
                                    const unsigned char *param, int plen,
                                    const EVP_MD *md, const EVP_MD *mgf1md)
{
  int seedlen = EVP_MD_size(md);
  unsigned char seed[64];
  assert(seedlen<=sizeof(seed));
  gen_random(seed, seedlen);
  int rv = RSA_padding_add_PKCS1_OAEP_ex(to, tlen, from, flen, param, plen, md, mgf1md, seed, seedlen);
  ub::secure_bzero(seed);
  return rv;
}

int rsa_key_t::RSA_padding_add_PKCS1_OAEP_ex(unsigned char *to, int tlen,
    const unsigned char *from, int flen,
    const unsigned char *param, int plen,
    const EVP_MD *md, const EVP_MD *mgf1md,
    const unsigned char *seed_data, int seedlen)
{
    int i, emlen = tlen - 1;
    unsigned char *db, *seed;
    unsigned char *dbmask, seedmask[EVP_MAX_MD_SIZE];
    int mdlen;

    if (md == NULL)
        md = EVP_sha1();
    if (mgf1md == NULL)
        mgf1md = md;

    mdlen = EVP_MD_size(md);
    assert(mdlen==seedlen);

    if (flen > emlen - 2 * mdlen - 1) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1,
               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return 0;
    }

    if (emlen < 2 * mdlen + 1) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1,
               RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    to[0] = 0;
    seed = to + 1;
    db = to + mdlen + 1;

    if (!EVP_Digest((void *)param, plen, db, NULL, md, NULL))
        return 0;
    memset(db + mdlen, 0, emlen - flen - 2 * mdlen - 1);
    db[emlen - flen - mdlen - 1] = 0x01;
    memcpy(db + emlen - flen - mdlen, from, (unsigned int)flen);

#if 0
    if (RAND_bytes(seed, mdlen) <= 0)
        return 0;
# ifdef PKCS_TESTVECT
    memcpy(seed,
           "\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2\xf0\x6c\xb5\x8f",
           20);
# endif
#else
  memmove(seed, seed_data, mdlen);
#endif

    dbmask = (unsigned char*)OPENSSL_malloc(emlen - mdlen);
    if (dbmask == NULL) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (PKCS1_MGF1_ex(dbmask, emlen - mdlen, seed, mdlen, mgf1md) < 0)
        return 0;
    for (i = 0; i < emlen - mdlen; i++)
        db[i] ^= dbmask[i];

    if (PKCS1_MGF1_ex(seedmask, mdlen, db, emlen - mdlen, mgf1md) < 0)
        return 0;
    for (i = 0; i < mdlen; i++)
        seed[i] ^= seedmask[i];

    OPENSSL_free(dbmask);
    return 1;
}

#if (OPENSSL_VERSION_NUMBER < 0x1000104fL)
int CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len)
	{
	size_t i;
	const unsigned char *a = (const unsigned char *)in_a;
	const unsigned char *b = (const unsigned char *)in_b;
	unsigned char x = 0;

	for (i = 0; i < len; i++)
		x |= a[i] ^ b[i];

	return x;
	}
#endif

int rsa_key_t::RSA_padding_check_PKCS1_OAEP_ex(unsigned char *to, int tlen,
                                      const unsigned char *from, int flen,
                                      int num, const unsigned char *param,
                                      int plen, const EVP_MD *md,
                                      const EVP_MD *mgf1md)
{
    int i, dblen, mlen = -1, one_index = 0, msg_index;
    unsigned int good, found_one_byte;
    const unsigned char *maskedseed, *maskeddb;
    /*
     * |em| is the encoded message, zero-padded to exactly |num| bytes: em =
     * Y || maskedSeed || maskedDB
     */
    unsigned char *db = NULL, *em = NULL, seed[EVP_MAX_MD_SIZE],
        phash[EVP_MAX_MD_SIZE];
    int mdlen;

    if (md == NULL)
        md = EVP_sha1();
    if (mgf1md == NULL)
        mgf1md = md;

    mdlen = EVP_MD_size(md);

    if (tlen <= 0 || flen <= 0)
        return -1;
    /*
     * |num| is the length of the modulus; |flen| is the length of the
     * encoded message. Therefore, for any |from| that was obtained by
     * decrypting a ciphertext, we must have |flen| <= |num|. Similarly,
     * num < 2 * mdlen + 2 must hold for the modulus irrespective of
     * the ciphertext, see PKCS #1 v2.2, section 7.1.2.
     * This does not leak any side-channel information.
     */
    if (num < flen || num < 2 * mdlen + 2)
        goto decoding_err;

    dblen = num - mdlen - 1;
    db = (unsigned char*)OPENSSL_malloc(dblen);
    em = (unsigned char*)OPENSSL_malloc(num);
    if (db == NULL || em == NULL) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    /*
     * Always do this zero-padding copy (even when num == flen) to avoid
     * leaking that information. The copy still leaks some side-channel
     * information, but it's impossible to have a fixed  memory access
     * pattern since we can't read out of the bounds of |from|.
     *
     * TODO(emilia): Consider porting BN_bn2bin_padded from BoringSSL.
     */
    memset(em, 0, num);
    memcpy(em + num - flen, from, flen);

    /*
     * The first byte must be zero, however we must not leak if this is
     * true. See James H. Manger, "A Chosen Ciphertext  Attack on RSA
     * Optimal Asymmetric Encryption Padding (OAEP) [...]", CRYPTO 2001).
     */
    good = constant_time_is_zero(em[0]);

    maskedseed = em + 1;
    maskeddb = em + 1 + mdlen;

    if (PKCS1_MGF1_ex(seed, mdlen, maskeddb, dblen, mgf1md))
        goto cleanup;
    for (i = 0; i < mdlen; i++)
        seed[i] ^= maskedseed[i];

    if (PKCS1_MGF1_ex(db, dblen, seed, mdlen, mgf1md))
        goto cleanup;
    for (i = 0; i < dblen; i++)
        db[i] ^= maskeddb[i];

    if (!EVP_Digest((void *)param, plen, phash, NULL, md, NULL))
        goto cleanup;

    good &= constant_time_is_zero(CRYPTO_memcmp(db, phash, mdlen));

    found_one_byte = 0;
    for (i = mdlen; i < dblen; i++) {
        /*
         * Padding consists of a number of 0-bytes, followed by a 1.
         */
        unsigned int equals1 = constant_time_eq(db[i], 1);
        unsigned int equals0 = constant_time_is_zero(db[i]);
        one_index = constant_time_select_int(~found_one_byte & equals1,
                                             i, one_index);
        found_one_byte |= equals1;
        good &= (found_one_byte | equals0);
    }

    good &= found_one_byte;

    /*
     * At this point |good| is zero unless the plaintext was valid,
     * so plaintext-awareness ensures timing side-channels are no longer a
     * concern.
     */
    if (!good)
        goto decoding_err;

    msg_index = one_index + 1;
    mlen = dblen - msg_index;

    if (tlen < mlen) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1, RSA_R_DATA_TOO_LARGE);
        mlen = -1;
    } else {
        memcpy(to, db + msg_index, mlen);
        goto cleanup;
    }

 decoding_err:
    /*
     * To avoid chosen ciphertext attacks, the error message should not
     * reveal which kind of decoding error happened.
     */
    RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1,
           RSA_R_OAEP_DECODING_ERROR);
 cleanup:
    if (db != NULL)
        OPENSSL_free(db);
    if (em != NULL)
        OPENSSL_free(em);
    return mlen;
}

bool rsa_key_t::pad_oaep(int bits, mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, byte_ptr out) // static
{
  int key_size = ub::bits_to_bytes(bits);
  return 0<RSA_padding_add_PKCS1_OAEP_ex(out, key_size, in.data, in.size, label.data, label.size, hash_alg_t::get(hash_alg).md,  hash_alg_t::get(mgf_alg).md);
}

buf_t rsa_key_t::pad_oaep(int bits, mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label) // static
{
  int key_size = ub::bits_to_bytes(bits);
  buf_t out(key_size);
  if (!pad_oaep(bits, in, hash_alg, mgf_alg, label, out.data())) out.free();
  return out;
}

int rsa_key_t::unpad_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, byte_ptr out) // static
{
  int key_size = in.size;
  buf_t temp;
  if (!out) out = temp.resize(key_size);
  return RSA_padding_check_PKCS1_OAEP_ex(out, key_size, in.data, key_size, key_size, label.data, label.size,  hash_alg_t::get(hash_alg).md,  hash_alg_t::get(mgf_alg).md); 
}

bool rsa_key_t::unpad_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, buf_t& out) // static
{
  int out_size = unpad_oaep(in, hash_alg, mgf_alg, label, nullptr);
  if (out_size<0) return false;
  unpad_oaep(in, hash_alg, mgf_alg, label, out.resize(out_size));
  return true;
}


bool rsa_key_t::encrypt_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, byte_ptr out)  const
{
  buf_t temp = pad_oaep(size()*8, in, hash_alg, mgf_alg, label);
  return encrypt_raw(temp.data(), out);
}

buf_t rsa_key_t::encrypt_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label) const
{
  buf_t temp = pad_oaep(size()*8, in, hash_alg, mgf_alg, label);
  buf_t out(size());
  if (!encrypt_raw(temp.data(), out.data())) out.free();
  return out;
}

int rsa_key_t::decrypt_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, byte_ptr out) const
{
  buf_t temp(size());
  if (!decrypt_raw(in.data, temp.data())) return -1;
  return unpad_oaep(temp, hash_alg, mgf_alg, label, out);
}

bool rsa_key_t::decrypt_oaep(mem_t in, hash_e hash_alg, hash_e mgf_alg, mem_t label, buf_t& out) const
{
  buf_t temp(size());
  if (!decrypt_raw(in.data, temp.data())) return false;
  return unpad_oaep(temp, hash_alg, mgf_alg, label, out);
}

} // namespace crypto