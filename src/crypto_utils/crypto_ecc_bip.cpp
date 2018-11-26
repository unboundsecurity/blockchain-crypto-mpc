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
#include "crypto_ecc_bip.h"

namespace crypto {

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    int size = int((pend - pbegin) * 138 / 100 + 1); // log(256) / log(58), rounded up.
    std::vector<unsigned char> b58(size);
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        int i = 0;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }

        assert(carry == 0);
        length = i;
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    std::vector<unsigned char>::iterator it = b58.begin() + (size - length);
    while (it != b58.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end())
        str += pszBase58[*(it++)];
    return str;
}


static std::string EncodeBase58(mem_t vch)
{
    return EncodeBase58(vch.data, vch.data + vch.size);
}

static std::string EncodeBase58Check(mem_t vchIn)
{
  buf_t vch(vchIn.size + 4);
  buf256_t hash = sha256_t::hash(vchIn);
  hash = sha256_t::hash(hash);
  memmove(vch.data(), vchIn.data, vchIn.size);
  memmove(vch.data() + vchIn.size, const_byte_ptr(hash), 4);
  return EncodeBase58(vch);
}

bip_node_t bip_node_t::from_master(mem_t S)
{
  static const char bitcoin_seed[] = "Bitcoin seed";
  buf_t I = hmac_sha512_t(mem_t(const_byte_ptr(bitcoin_seed), sizeof(bitcoin_seed)-1)).calculate(S);

  bip_node_t result;
  //result.k_part = buf256_t::load(I.data());

  bn_t key = bn_t::from_bin(mem_t(I.data(), 32)) % curve_k256.order();
  key.to_bin(result.k_par, 32);


  result.c_par = buf256_t::load(I.data()+32);
  result.level = 0;
  result.parent_fingerprint = 0;
  result.child_number = 0;

  return result;
}

bn_t bip_node_t::get_private_key() const
{
  return bn_t(k_par);
}

ecc_point_t bip_node_t::get_public_key() const
{
  bn_t x = get_private_key();
  return curve_k256.generator() * x;
}

bip_node_t bip_node_t::derive(bool hardened, unsigned index) const
{
  buf_t I;

  if (hardened)
  {
    index|=0x80000000;
    byte_t zero = 0;
    I = hmac_sha512_t(c_par).calculate(zero, k_par, index);
  }
  else
  {
    I = hmac_sha512_t(c_par).calculate(get_public_key(), index);
  }

  bn_t old_k = bn_t(k_par);
  bn_t delta = bn_t::from_bin(mem_t(I.data(), 32));
  bn_t new_k = (old_k + delta) % curve_k256.order();

  bip_node_t result;
  new_k.to_bin(result.k_par, 32);
  result.c_par = buf256_t::load(I.data()+32);
  result.level = level+1;
  result.child_number = index;

  buf_t ripemd_hash = crypto::ripemd160_t::hash(sha256_t::hash(get_public_key().to_compressed_oct()));
  result.parent_fingerprint = ub::be_get_4(ripemd_hash.data());
  return result;
}


std::string bip_node_t::serialize_pub(mem_t pub_key_oct, bool main) const
{
  assert(pub_key_oct.size==33);

  unsigned version = main ? 0x0488B21E : 0x043587CF;

  buf_t out(78);
  ub::be_set_4(out.data()+0, version);
  out[4] = level;
  ub::be_set_4(out.data()+5, parent_fingerprint);
  ub::be_set_4(out.data()+9, child_number);
  c_par.save(out.data() + 13);

  memmove(out.data()+45, pub_key_oct.data, 33);
  return EncodeBase58Check(out);
}

std::string bip_node_t::serialize_pub(bool main) const
{
  return serialize_pub(get_public_key().to_compressed_oct(), main);
}

std::string bip_node_t::serialize_prv(bool main) const
{
  unsigned version = main ? 0x0488ADE4 : 0x04358394;

  buf_t out(4+1+4+4+32+33);
  ub::be_set_4(out.data()+0, version);
  out[4] = level;
  ub::be_set_4(out.data()+5, parent_fingerprint);
  ub::be_set_4(out.data()+9, child_number);
  c_par.save(out.data() + 13);

  out[45] = 0;
  k_par.save(out.data() + 46);
  return EncodeBase58Check(out);
}


// -----------------------------------------------------------------------------------------------

static buf_t pub_key_to_oct(const crypto::ecp_25519_t& point)
{
  buf_t out(33);
  out[0] = 0;
  point.encode(out.data()+1);
  return out;
}

bip_node_ed25519_t bip_node_ed25519_t::from_master(mem_t S)
{
  static const char bitcoin_seed[] = "Bitcoin seed";
  buf_t I = hmac_sha512_t(mem_t(const_byte_ptr(bitcoin_seed), sizeof(bitcoin_seed)-1)).calculate(S);

  bip_node_ed25519_t result;

  bn_t key = bn_t::from_bin(mem_t(I.data(), 32)) % crypto::ec25519::order();
  key.to_bin(result.k_par, 32);

  result.c_par = buf256_t::load(I.data()+32);
  result.level = 0;
  result.parent_fingerprint = 0;
  result.child_number = 0;

  return result;
}

bip_node_ed25519_t bip_node_ed25519_t::derive(bool hardened, unsigned index) const
{
  buf_t I;

  if (hardened)
  {
    index|=0x80000000;
    byte_t zero = 0;
    I = hmac_sha512_t(c_par).calculate(zero, k_par, index);
  }
  else
  {
    I = hmac_sha512_t(c_par).calculate(pub_key_to_oct(get_public_key()), index);
  }

  bn_t old_k = bn_t(k_par);
  bn_t delta = bn_t::from_bin(mem_t(I.data(), 32));
  bn_t new_k = (old_k + delta) % crypto::ec25519::order();

  bip_node_ed25519_t result;
  new_k.to_bin(result.k_par, 32);
  result.c_par = buf256_t::load(I.data()+32);
  result.level = level+1;
  result.child_number = index;

  buf_t ripemd_hash = crypto::ripemd160_t::hash(sha256_t::hash(pub_key_to_oct(get_public_key())));
  result.parent_fingerprint = ub::be_get_4(ripemd_hash.data());
  return result;
}


bn_t bip_node_ed25519_t::get_private_key() const
{
  return bn_t(k_par);
}

crypto::ecp_25519_t bip_node_ed25519_t::get_public_key() const
{
  bn_t x = get_private_key();
  return crypto::ec25519::generator() * x;
}

std::string bip_node_ed25519_t::serialize_pub(mem_t pub_key_oct, bool main) const
{
  assert(pub_key_oct.size==33);

  unsigned version = main ? 0x0488B21E : 0x043587CF;

  buf_t out(78);
  ub::be_set_4(out.data()+0, version);
  out[4] = level;
  ub::be_set_4(out.data()+5, parent_fingerprint);
  ub::be_set_4(out.data()+9, child_number);
  c_par.save(out.data() + 13);

  memmove(out.data()+45, pub_key_oct.data, 33);
  return EncodeBase58Check(out);
}

std::string bip_node_ed25519_t::serialize_pub(bool main) const
{
  return serialize_pub(pub_key_to_oct(get_public_key()), main);
}

std::string bip_node_ed25519_t::serialize_prv(bool main) const
{
  unsigned version = main ? 0x0488ADE4 : 0x04358394;

  buf_t out(4+1+4+4+32+33);
  ub::be_set_4(out.data()+0, version);
  out[4] = level;
  ub::be_set_4(out.data()+5, parent_fingerprint);
  ub::be_set_4(out.data()+9, child_number);
  c_par.save(out.data() + 13);

  out[45] = 0;
  k_par.save(out.data() + 46);
  return EncodeBase58Check(out);
}

}