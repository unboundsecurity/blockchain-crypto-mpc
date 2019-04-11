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
#include "mpc_core.h"
#include "mpc_eddsa.h"

using namespace ub;
using namespace crypto;

namespace mpc {


void zk_dl_25519_t::p(const ecp_25519_t& Q, mem_t session_id, uint8_t aux, const bn_t& d)
{
  bn_t order = ec25519::order();
	bn_t sigma = bn_t::rand(order);
  const ecp_gen_25519_t& G = ec25519::generator();
  ecp_25519_t X = G * sigma;

  buf256_t hash = sha256_t::hash(G, Q, X, session_id, aux);
  e = bn_t(hash);
	
  MODULO(order)
  {
    u = e * d + sigma;
  }
}

bool zk_dl_25519_t::v(const ecp_25519_t& Q, mem_t session_id, uint8_t aux) const
{
  const ecp_gen_25519_t& G = ec25519::generator();
  ecp_25519_t T = Q;
  T.invert();

  ecp_25519_t X = G * u + T * e;

  buf256_t hash = sha256_t::hash(G, Q, X, session_id, aux);
  bn_t etag = bn_t(hash);
  return etag == e;
}


//----------------------------------------------------------------------------

void zk_ddh_25519_t::p(
  const ecp_25519_t& Q, 
  const ecp_25519_t& A, 
  const ecp_25519_t& B, 
  const bn_t& w, 
  mem_t session_id,
  uint8_t aux)  // output
{
  bn_t order = ec25519::order();
	bn_t sigma = bn_t::rand(order);

  const ecp_gen_25519_t& G = ec25519::generator();
  
  ecp_25519_t X = G * sigma;
  ecp_25519_t Y = Q * sigma;

  buf256_t hash = sha256_t::hash(G, Q, A, B, X, Y, session_id, aux);
  e = bn_t(hash);
  
  MODULO(order)  { u = sigma + e * w; }
}

bool zk_ddh_25519_t::v(
  const ecp_25519_t& Q, 
  const ecp_25519_t& A,
  const ecp_25519_t& B, 
  mem_t session_id,
  uint8_t aux) const
{
  const ecp_gen_25519_t& G = ec25519::generator();

  ecp_25519_t X = G * u - A * e;
  ecp_25519_t Y = Q * u - B * e;

  buf256_t hash = sha256_t::hash(G, Q, A, B, X, Y, session_id, aux);
  bn_t etag = bn_t(hash);
  return etag == e;
}



// ----------------------------- eddsa_share_t -------------------------------
void eddsa_share_t::split(
  mem_t prv_key, 
  /*OUT*/ eddsa_share_t& share1, 
  /*OUT*/ eddsa_share_t& share2) // static
{
  bn_t order = ec25519::order();
  share1.x = bn_t::rand(order);
  share2.x = (ec25519::decode_scalar(prv_key) - share1.x) % order;

  bn_t kdf1_key = curve_p256.get_random_value();
  bn_t kdf2_key = curve_p256.get_random_value();
  ecdh_share_t::split(curve_p256, kdf1_key, share1.kdf1, share2.kdf1);
  ecdh_share_t::split(curve_p256, kdf2_key, share1.kdf2, share2.kdf2);

  const ecp_gen_25519_t& G = crypto::ec25519::generator();
  share1.Q_full = share2.Q_full = G * share1.x + G * share2.x;
}


void eddsa_share_t::refresh(bool add, mem_t diff)
{
  assert(diff.size>=64*3);

  mem_t v_buf = mem_t(diff.data, 64);
  mem_t v_kdf1_buf = mem_t(diff.data+64, 64);
  mem_t v_kdf2_buf = mem_t(diff.data+64+64, 64);

  bn_t order = ec25519::order();
  const bn_t& order_kdf = curve_p256.order();

  bn_t v = bn_t::from_bin(v_buf) % order;
  bn_t v_kdf1 = bn_t::from_bin(v_kdf1_buf) % order_kdf;
  bn_t v_kdf2 = bn_t::from_bin(v_kdf2_buf) % order_kdf;

  MODULO(order)
  {
    if (add) x += v; else x -= v;
  }

  kdf1.refresh(add, v_kdf1);
  kdf2.refresh(add, v_kdf2);
}

// ----------------------------- eddsa_gen_t -------------------------------
error_t eddsa_gen_t::peer1_step1(
  mem_t session_id, 
  eddsa_share_t& share,
  message1_t& out)
{
  error_t rv = 0;
  this->session_id = session_id;

  bn_t order = ec25519::order();
  const ecp_gen_25519_t& G = ec25519::generator();
  bn_t s1 = bn_t::rand(order);
  share.x = s1;
  A1 = G * s1;

  zk_dl.p(A1, session_id, 1, s1); 
  
  commitment_t comm;
  comm.gen(sha256_t(session_id, A1, zk_dl.e, zk_dl.u));
  out.comm_hash = comm.hash;
  comm_rand = comm.rand;

  kdf1.peer1_step1(curve_p256, session_id, share.kdf1, out.kdf1_gen_message1);
  return rv;
}

error_t eddsa_gen_t::peer2_step1(
  mem_t session_id, 
  eddsa_share_t& share,
  const message1_t& in,
  message2_t& out)
{
  error_t rv = 0;
  this->session_id = session_id;
  comm_hash = in.comm_hash;

  bn_t order = ec25519::order();
  const ecp_gen_25519_t& G = ec25519::generator();
  bn_t s2 = bn_t::rand(order);
  share.x = s2;
  out.A2 = A2 = G * s2;

  bn_t x = ec25519::rand();
  out.a = G * x;
  out.b = out.a * s2;
  out.zk_ddh.p(out.a, A2, out.b, s2, session_id, 2); 

  if (rv = kdf1.peer2_step1(curve_p256, session_id, share.kdf1, in.kdf1_gen_message1, out.kdf1_gen_message2)) return rv;
  kdf2.peer1_step1(curve_p256, session_id, share.kdf2, out.kdf2_gen_message1);
  return rv;
}

error_t eddsa_gen_t::peer1_step2(
  eddsa_share_t& share,
  const message2_t& in,
  message3_t& out)
{
  error_t rv = 0;

  if (!ec25519::check(in.A2)) return rv = error(E_CRYPTO);
  if (!ec25519::check(in.a)) return rv = error(E_CRYPTO);
  if (!ec25519::check(in.b)) return rv = error(E_CRYPTO);
  if (!in.zk_ddh.v(in.a, in.A2, in.b, session_id, 2)) return rv = error(E_CRYPTO); 

  if (rv = kdf1.peer1_step2(share.kdf1, in.kdf1_gen_message2, out.kdf1_gen_message3)) return rv;
  if (rv = kdf2.peer2_step1(curve_p256, session_id, share.kdf2, in.kdf2_gen_message1, out.kdf2_gen_message2)) return rv;

  ecp_25519_t A = A1 + in.A2;
  if (!ec25519::check(A)) return rv = error(E_CRYPTO);
  share.Q_full = A;
  
  out.zk_dl = zk_dl;
  out.A1 = A1;
  out.comm_rand = comm_rand;
  return rv;
}

error_t eddsa_gen_t::peer2_step2(
    eddsa_share_t& share,
    const message3_t& in,
    message4_t& out)
{
  error_t rv = 0;

  if (!ec25519::check(in.A1)) return rv = error(E_CRYPTO);

  if (!commitment_t::check(in.comm_rand, comm_hash, 
    sha256_t(session_id, in.A1, in.zk_dl.e, in.zk_dl.u))) return rv = error(E_CRYPTO);
 
  if (!in.zk_dl.v(in.A1, session_id, 1)) return rv = error(E_CRYPTO);

  if (rv = kdf2.peer1_step2(share.kdf2, in.kdf2_gen_message2, out)) return rv;
  if (rv = kdf1.peer2_step2(share.kdf1, in.kdf1_gen_message3)) return rv;

  ecp_25519_t A = in.A1 + A2;
  if (!ec25519::check(A)) return rv = error(E_CRYPTO);
  share.Q_full = A;

  return rv;
}

error_t eddsa_gen_t::peer1_step3(
  eddsa_share_t& share,
  const message4_t& in)
{
  return kdf2.peer2_step2(share.kdf2, in);
}


// ----------------------------- eddsa_sign_t -------------------------------
ecc_point_t tweak_to_point(mem_t tweak) // static
{
  bn_t p, a, b;
  crypto::curve_p256.get_params(p, a, b);

  buf256_t h = crypto::random_oracle_hash(tweak);

  bn_t x = bn_t(h) % p;

  ecc_point_t point(crypto::curve_p256);

  while (!point.set_compressed_coordinates(x, 0) && 
         !point.set_compressed_coordinates(x, 1))
  {
    MODULO(p) { x++; }
  }

  return point;
}


error_t eddsa_sign_t::peer1_step1(
  mem_t data_to_sign, 
  bool prove_mode, 
  const eddsa_share_t& share,
  /*OUT*/message1_t& out)
{
  error_t rv = 0;
  kdf_PUB_KEY = tweak_to_point(data_to_sign);
  buf_t kdf1_session_id = sha256_t::hash(data_to_sign, share.Q_full);

  if (rv = kdf1_ctx.peer1_init(kdf_PUB_KEY, prove_mode, kdf1_session_id, share.kdf1, out.kdf1_message1)) return rv;

  agree1 = out.agree1 = crypto::gen_random(16);

  this->prove_mode = prove_mode;
  this->data_to_sign = data_to_sign;

  return 0;
}

error_t eddsa_sign_t::peer2_step1(
  mem_t data_to_sign, 
  bool prove_mode, 
  const eddsa_share_t& share,
  const message1_t& in,
  /*OUT*/message2_t& out)
{
  error_t rv = 0;
  this->prove_mode = prove_mode;
  this->data_to_sign = data_to_sign;

  if (in.agree1.size()<16) return rv = error(E_BADARG);
  out.agree2 = crypto::gen_random(16);

  kdf_PUB_KEY = tweak_to_point(data_to_sign);
  buf_t kdf1_session_id = sha256_t::hash(data_to_sign, share.Q_full);

  if (rv = kdf1_ctx.peer2_exec(kdf_PUB_KEY, share.kdf1, prove_mode, kdf1_session_id, in.kdf1_message1, out.kdf1_message2, kdf1_result)) return rv;
  kdf1_result = sha512_t::hash(kdf1_result);

  session_id = sha256_t::hash(in.agree1, out.agree2, data_to_sign);
  if (rv = kdf2_ctx.peer1_init(kdf_PUB_KEY, prove_mode, session_id, share.kdf2, out.kdf2_message1)) return rv;

  return 0;
}

error_t eddsa_sign_t::peer1_step2(
  const eddsa_share_t& share,
  const message2_t& in,
  /*OUT*/message3_t& out)
{
  error_t rv = 0;
  if (in.agree2.size()<16) return rv = error(E_BADARG);

  if (rv = kdf1_ctx.peer1_final(share.kdf1, in.kdf1_message2, kdf1_result)) return rv;
  kdf1_result = sha512_t::hash(kdf1_result);

  session_id = sha256_t::hash(agree1, in.agree2, data_to_sign);
  if (rv = kdf2_ctx.peer2_exec(kdf_PUB_KEY, share.kdf2, prove_mode, session_id, in.kdf2_message1, out.kdf2_message2, kdf2_result)) return rv;

  kdf2_result = sha512_t::hash(kdf2_result);

  r_reduced_buf = ec25519::reduce_scalar_64(kdf1_result);
  R1 = ec25519::mul_to_generator(r_reduced_buf);
  
  commitment_t comm;
  comm.gen(sha256_t(session_id, R1));
  out.comm_hash = comm.hash;
  comm_rand = comm.rand;

  return 0;
}

error_t eddsa_sign_t::peer2_step2(
  const eddsa_share_t& share,
  const message3_t& in,
  message4_t& out)
{
  error_t rv = 0;
  if (rv = kdf2_ctx.peer1_final(share.kdf2, in.kdf2_message2, kdf2_result)) return rv;

  kdf2_result = sha512_t::hash(kdf2_result);

  comm_hash = in.comm_hash;
  r_reduced_buf = ec25519::reduce_scalar_64(kdf2_result);
  R2 = ec25519::mul_to_generator(r_reduced_buf);

  out.R2 = R2;
  return 0;
}

error_t eddsa_sign_t::peer1_step3(
  const eddsa_share_t& share,
  const message4_t& in,
  /*OUT*/message5_t& out)
{
  error_t rv = 0;
  if (!ec25519::check(in.R2)) return rv = error(E_BADARG);
  R2 = in.R2;

  out.R1 = R1;
  out.comm_rand = comm_rand;
  return 0;
}

error_t eddsa_sign_t::peer2_step3(
  const eddsa_share_t& share,
  const message5_t& in,
  message6_t& out)
{
  error_t rv = 0;

  if (!ec25519::check(in.R1)) return rv = error(E_BADARG);
  if (!commitment_t::check(in.comm_rand, comm_hash, sha256_t(session_id, in.R1))) return rv = error(E_CRYPTO);

  crypto::ecp_25519_t R_sum = R2 + in.R1;
  buf_t R_sum_value = R_sum.encode();
  
  buf_t pub_key = share.Q_full.encode();
  buf_t HRAM = sha512_t::hash(R_sum_value, pub_key, data_to_sign);
  buf_t HRAM_reduced = ec25519::reduce_scalar_64(HRAM);
  const crypto::bn_t& x2 = share.x;
  out.s2 = ec25519::scalar_muladd(HRAM_reduced, ec25519::encode_scalar(x2), r_reduced_buf);

  return 0;
}

error_t eddsa_sign_t::peer1_step4(
  const eddsa_share_t& share,
  const message6_t& in,
  byte_ptr out)
{
  error_t rv = 0;

  ecp_25519_t R_sum = R1 + R2;
  buf_t R_sum_value = R_sum.encode();
  
  buf_t pub_key = share.Q_full.encode();
  buf_t HRAM = sha512_t::hash(R_sum_value, pub_key, data_to_sign);
  buf_t HRAM_reduced = ec25519::reduce_scalar_64(HRAM);
  const crypto::bn_t& x1 = share.x;
  buf_t s1 = ec25519::scalar_muladd(HRAM_reduced, ec25519::encode_scalar(x1), r_reduced_buf);

  bn_t order = crypto::ec25519::order();
  bn_t S_value = (ec25519::decode_scalar(s1) + ec25519::decode_scalar(in.s2)) % order;
  buf_t signature = R_sum.encode() + ec25519::encode_scalar(S_value);

  crypto::eddsa_key_t key;
  key.set_pub_key(pub_key);
  bool ok = key.verify(data_to_sign, signature);
  if (!ok) return rv = error(E_CRYPTO);

  memmove(out, signature.data(), 64);
  return 0;
}


} // namespace mpc
