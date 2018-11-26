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
#include "mpc_ecdh.h"
#include "mpc_ecdsa.h"

using namespace ub;
using namespace crypto;

namespace mpc {

int get_safe_paillier_bits(ecurve_t curve)
{
  return 2048;//std::max(2048, curve.bits()*4 + 2);
}

// --------------------------------- ecdsa_share_t --------------------------------

error_t ecdsa_share_t::get_refresh_delta(ecurve_t curve, mem_t refresh_buf, bn_t& delta)
{
  error_t rv = 0;
  int key_size = curve.size();
  if (refresh_buf.size!=2*key_size) return rv = ub::error(E_BADARG);

  const bn_t& order = curve.order();
  delta = bn_t::from_bin(refresh_buf) % order;
  return 0;
}

error_t ecdsa_share_t::refresh_peer1(const bn_t& delta)
{
  ecurve_t curve = get_curve();
  const ecc_generator_point_t& G = curve.generator();
  const bn_t& order = curve.order();
  MODULO (order) 
  { 
    x += delta;
  }
  return 0;
}

error_t ecdsa_share_t::refresh_peer2(const bn_t& delta)
{
  ecurve_t curve = get_curve();
  const ecc_generator_point_t& G = curve.generator();
  const bn_t& order = curve.order();

  MODULO (order) 
  { 
    x -= delta;
  }

  return 0;
}

//------------------------ ecdsa_refresh_paillier_t---------------------------------

error_t ecdsa_create_paillier_t::peer1_step1(ecdsa_share_t& share, mem_t session_id, message1_t& out)
{
  ecurve_t curve = share.get_curve();
  int paillier_size = get_safe_paillier_bits(curve);

  share.paillier.generate(paillier_size);
  out.N = share.paillier.get_N();
  share.r_key = bn_t::rand(out.N);

  share.c_key = out.c_key = share.paillier.encrypt(share.x, share.r_key);
  const ecc_generator_point_t& G = curve.generator();
  out.pi = ZK_PAILLIER_P_non_interactive(out.N, share.paillier.get_phi_N(), session_id);
  //out.zk_pdl.p(curve, G * share.x, out.c_key, share.paillier, session_id, 1, share.r_key, share.x); 

  return 0;
}

error_t ecdsa_create_paillier_t::peer2_step2(ecdsa_share_t& share, mem_t session_id, const message1_t& in)
{
  error_t rv = 0;

  ecurve_t curve = share.get_curve();
  int paillier_size = get_safe_paillier_bits(curve);

  if (in.N.get_bits_count() < paillier_size) return rv = error(E_CRYPTO);
  share.c_key = in.c_key;
  share.paillier.create_pub(in.N);

  if (!ZK_PAILLIER_V_non_interactive(in.N, in.pi, session_id)) return rv = error(E_CRYPTO);
  //if (!in.zk_pdl.v(curve, share.Q_other, in.c_key, in.N, session_id, 1)) return rv = error(E_CRYPTO); 

  return 0;
}


//------------------------ ecdsa_refresh_paillier_t---------------------------------

error_t ecdsa_refresh_paillier_t::peer1_step(ecdsa_share_t& share, mem_t session_id, const ecdsa_share_t& old_share, const bn_t& delta)
{
  ecurve_t curve = share.get_curve();
  int paillier_size = get_safe_paillier_bits(curve);

  share.paillier.generate(paillier_size);
  N = share.paillier.get_N();
  share.r_key = bn_t::rand(N);

  const crypto::paillier_t& paillier1 = old_share.paillier;
  const crypto::paillier_t& paillier2 = share.paillier;

  bn_t n1 = paillier1.get_N();
  bn_t n2 = paillier2.get_N();
   
  bn_t r1 = old_share.r_key;
  bn_t r2 = share.r_key;

  bn_t c1 = old_share.c_key;

  bn_t temp = paillier1.decrypt(c1);
  bn_t c2 = paillier2.encrypt(temp, r2);

  zk_paillier_eq.p(temp, r1, r2, session_id, n1, c1, n2, c2);
  share.c_key = c_key = share.paillier.add_scalar(c2, delta);

  return 0;
}

error_t ecdsa_refresh_paillier_t::peer2_step(ecdsa_share_t& share, mem_t session_id, const ecdsa_share_t& old_share, const bn_t& delta) const
{
  error_t rv = 0;

  ecurve_t curve = share.get_curve();
  int paillier_size = get_safe_paillier_bits(curve);

  if (N.get_bits_count() < paillier_size) return rv = error(E_CRYPTO);
  share.c_key = c_key;
  share.paillier.create_pub(N);

  if (zk_paillier_eq.c1 != old_share.c_key)
  {
    return rv = ub::error(E_CRYPTO);
  }

  const crypto::paillier_t& paillier1 = old_share.paillier;
  const crypto::paillier_t& paillier2 = share.paillier;


  bn_t n1 = paillier1.get_N();
  bn_t n2 = paillier2.get_N();
  if (!zk_paillier_eq.v(session_id, n1, n2))
  {
    return rv = ub::error(E_CRYPTO);
  }

  // recalculate c_key
  bn_t new_c_key = paillier2.add_scalar(zk_paillier_eq.c2, delta);

  if (c_key!=new_c_key)
  {
    return rv = ub::error(E_CRYPTO);
  }

  return 0;
}

// ------------------------------ ecdsa_generate_t ----------------------
void ecdsa_generate_t::peer1_step1(
    bool only_helper,
    ecurve_t curve, 
    mem_t session_id, 
    ecdsa_share_t& share,
    message1_t& out)
{
  this->session_id = session_id;

  const bn_t& q = curve.order();
  if (!only_helper) 
  {
    share.x = curve.get_random_value();
  }

  const ecc_generator_point_t& G = curve.generator();
  Q_self = G * share.x;

  zk_dl.p(curve, Q_self, session_id, 1, share.x);  
  commitment_t comm;  comm.gen(sha256_t(session_id, Q_self, zk_dl.e, zk_dl.u));

  out.comm_hash = comm.hash;
  comm_rand = comm.rand;
}

error_t ecdsa_generate_t::peer2_step1(
  bool only_helper,
  ecurve_t curve, 
  mem_t session_id, 
  ecdsa_share_t& share,
  const message1_t& in, 
  message2_t& out)
{
  error_t rv = 0;
  this->session_id = session_id;

  comm_hash = in.comm_hash;
  const ecc_generator_point_t& G = curve.generator();
  if (!only_helper) 
  {
    share.x = curve.get_random_value();
  }


  out.Q2 = Q_self = G * share.x;
  out.zk_dl.p(curve, Q_self, session_id, 2, share.x);

  return 0;
}

error_t ecdsa_generate_t::peer1_step2(
  ecdsa_share_t& share,
  const message2_t& in,
  message3_t& out)
{
  error_t rv = 0;
  ecurve_t curve = Q_self.get_curve();
  if (!curve.check(in.Q2)) return rv = error(E_CRYPTO);
  if (!in.zk_dl.v(curve, in.Q2, session_id, 2)) return rv = error(E_CRYPTO);

  const ecc_generator_point_t& G = curve.generator();

  share.Q_full = in.Q2 + G * share.x;

  out.Q1 = Q_self;
  out.comm_rand = comm_rand;
  out.zk_dl = zk_dl;
  if (rv = create_paillier.peer1_step1(share, session_id, out.create_paillier_msg1)) return rv;

  return 0;
}


error_t ecdsa_generate_t::peer2_step2(
  ecdsa_share_t& share,
  const message3_t& in)
{
  error_t rv = 0;

  ecurve_t curve = Q_self.get_curve();
  if (!curve.check(in.Q1)) return rv = error(E_CRYPTO);

  if (!commitment_t::check(in.comm_rand, comm_hash, sha256_t(session_id, in.Q1, in.zk_dl.e, in.zk_dl.u))) return rv = error(E_CRYPTO);
  if (!in.zk_dl.v(curve, in.Q1, session_id, 1)) return rv = error(E_CRYPTO);

  const ecc_generator_point_t& G = curve.generator();

  share.Q_full = in.Q1 + G * share.x;

  if (rv = create_paillier.peer2_step2(share, session_id, in.create_paillier_msg1)) return rv;

  return 0;
}


// ----------------------------------------- ecdsa_sign_t ------------------------------------------------

void ecdsa_sign_t::peer1_step1(
  const ecdsa_share_t& share, 
  mem_t data_to_sign,
  bool refresh,
  message1_t& out)
{
  this->refresh = refresh;
  this->data_to_sign = data_to_sign;

  ecurve_t curve = share.get_curve();
  const ecc_generator_point_t& G = curve.generator();

  buf_t initial_session_id = sha256_t::hash(data_to_sign, share.Q_full);

  k1 = curve.get_random_value();
  R1 = G * k1;
  zk_dl.p(curve, R1, initial_session_id, 1, k1);

  commitment_t comm; comm.gen(sha256_t(initial_session_id, R1, zk_dl.e, zk_dl.u));

  agree1 = out.agree1 = crypto::gen_random(16);
  out.comm_hash = comm.hash;
  comm_rand = comm.rand;
}

error_t ecdsa_sign_t::peer2_step1(
  const ecdsa_share_t& share, 
  mem_t data_to_sign,
  bool refresh,
  const message1_t& in,
  message2_t& out)
{
  error_t rv = 0;
  if (in.agree1.size()<16) return rv = error(E_BADARG);
  out.agree2 = crypto::gen_random(16);

  this->refresh = refresh;
  this->data_to_sign = data_to_sign;

  ecurve_t curve = share.get_curve();
  int key_size = share.get_curve().size();
  const ecc_generator_point_t& G = curve.generator();

  session_id = sha256_t::hash(in.agree1, out.agree2, data_to_sign);
  if (refresh) agree_refresh = agree_random_t::generate(key_size*2, in.agree1 + out.agree2 + data_to_sign);

  comm_hash = in.comm_hash;

  k2 = curve.get_random_value();
  out.R2 = R2 = G * k2;
  out.zk_dl.p(curve, R2, session_id, 2, k2);

  return 0;
}

error_t ecdsa_sign_t::peer1_step2(
  const ecdsa_share_t& share, 
  const message2_t& in,
  message3_t& out)
{
  error_t rv = 0;
  if (in.agree2.size()<16) return rv = error(E_BADARG);
  ecurve_t curve = share.get_curve();
  int key_size = share.get_curve().size();

  session_id = sha256_t::hash(agree1, in.agree2, data_to_sign);
  if (refresh) agree_refresh = agree_random_t::generate(key_size*2, agree1 + in.agree2 + data_to_sign);

  if (!curve.check(in.R2)) return rv = error(E_CRYPTO);
  if (!in.zk_dl.v(curve, in.R2, session_id, 2)) return rv = error(E_CRYPTO);

  out.zk_dl = zk_dl;
  out.comm_rand = comm_rand;
  out.R1 = R1;

  R2 = in.R2;
  return 0;
}

error_t ecdsa_sign_t::peer2_step2(
    const ecdsa_share_t& share, 
    const message3_t& in,
    message4_t& out)
{
  error_t rv = 0;
  ecurve_t curve = share.get_curve();
  const bn_t& q = curve.order();

  if (!curve.check(in.R1)) return rv = error(E_CRYPTO);

  buf_t initial_session_id = sha256_t::hash(data_to_sign, share.Q_full);

  if (!commitment_t::check(in.comm_rand, comm_hash, sha256_t(initial_session_id, in.R1, in.zk_dl.e, in.zk_dl.u))) return rv = error(E_CRYPTO);
  if (!in.zk_dl.v(curve, in.R1, initial_session_id, 1)) return rv = error(E_CRYPTO);
  ecc_point_t R = in.R1 * k2;

  bn_t u, v;
  bn_t r = R.get_x() % q;

  bn_t m_tag = bn_t::from_bin(data_to_sign);

  bn_t rho = bn_t::rand((q*q) << 208); // 128 + 80 (needed to ensure statistical closeness, even though over integers)
  MODULO(q) u = m_tag / k2;  
  bn_t u2 = rho*q + u;
  MODULO(q) v = r / k2;  

  bn_t c1 = share.paillier.add_scalar(share.c_key, share.x);
  c1 = share.paillier.add_scalar(c1, q << 208); // 128 + 80 (needed to ensure that is positive, due to slack in range proof)
  bn_t c2 = share.paillier.mul_scalar(c1, v);
  out.c3 = share.paillier.add_scalar(c2, u2);

  return 0;
}

error_t ecdsa_sign_t::peer1_step3(
  ecdsa_share_t& share, 
  const message4_t& in,
  message5_t& out)
{
  error_t rv = 0;
  ecurve_t curve = share.get_curve();
  const bn_t& q = curve.order();

  bn_t s_tag = share.paillier.decrypt(in.c3);
    
  bn_t s_tag2;
  MODULO(q) s_tag2 = k1.inv() * s_tag;  

  bn_t s = s_tag2;
  bn_t s_reduced = q - s_tag2;
  if (s_reduced < s) s = s_reduced;

  ecc_point_t R = R2 * k1;

  bn_t r = R.get_x() % q; 

  ecdsa_signature_t sig(curve, r, s); 

  // verify
  ecc_key_t ecc_verify_key;
  ecc_verify_key.set_pub_key(share.Q_full); 
  if (!ecc_verify_key.ecdsa_verify(data_to_sign, sig)) return rv = error(E_CRYPTO); 
  
  out.signature = sig.to_bin();

  if (refresh)
  {
    ecdsa_share_t old_share = share;
    bn_t delta;
    if (rv = ecdsa_share_t::get_refresh_delta(curve, agree_refresh, delta)) return rv;
    if (rv = share.refresh_peer1(delta)) return rv;
    if (rv = out.refresh_paillier.peer1_step(share, session_id, old_share, delta)) return rv;
  }

  return 0;
}

error_t ecdsa_sign_t::peer2_step3(
  ecdsa_share_t& share, 
  const message5_t& in)
{
  error_t rv = 0;
  ecurve_t curve = share.get_curve();

  ecc_key_t ecc_verify_key;
  ecc_verify_key.set_pub_key(share.Q_full); 

  ecdsa_signature_t sig = ecdsa_signature_t::from_bin(curve, in.signature); 
  if (!ecc_verify_key.ecdsa_verify(data_to_sign, sig)) return rv = error(E_CRYPTO); 

  if (refresh)
  {
    ecdsa_share_t old_share = share;
    bn_t delta;
    if (rv = ecdsa_share_t::get_refresh_delta(curve, agree_refresh, delta)) return rv;
    if (rv = share.refresh_peer2(delta)) return rv;

    const bn_t& order = curve.order();
    bn_t x_delta = bn_t::from_bin(agree_refresh) % order;
    if (rv = in.refresh_paillier.peer2_step(share, session_id, old_share, delta)) return rv;
  }

  return 0;
}

// ----------------------------- refresh ------------------------------

void ecdsa_refresh_t::peer1_step1(
  const ecdsa_share_t& share, 
  message1_t& out)
{
  int key_size = share.get_curve().size();
  agree_random.set_size(16 + key_size*2);
  agree_random.peer1_step1(out);
}


error_t ecdsa_refresh_t::peer2_step1(
  const ecdsa_share_t& share, 
  const message1_t& in,
  message2_t& out)
{
  int key_size = share.get_curve().size();
  agree_random.set_size(16 + key_size*2);
  
  return agree_random.peer2_step1(in, out.agree_msg2);
}


error_t ecdsa_refresh_t::peer1_step2(
  ecdsa_share_t& share, 
  const message2_t& in,
  message3_t& out)
{
  buf_t agree_buf;
  error_t rv =  agree_random.peer1_step2(in.agree_msg2, out.agree_msg3, agree_buf);
  if (rv) return rv;

  ecurve_t curve = share.get_curve();
  int key_size = curve.size();
  if (agree_buf.size()!=16 + key_size*2) return rv = ub::error(E_BADARG);

  mem_t session_id = mem_t(agree_buf.data(), 16);
  mem_t agree_refresh = mem_t(agree_buf.data()+16, agree_buf.size()-16);

  ecdsa_share_t old_share = share;
  bn_t delta;
  if (rv = ecdsa_share_t::get_refresh_delta(curve, agree_refresh, delta)) return rv;
  if (rv = share.refresh_peer1(delta)) return rv; 
  if (rv = out.refresh_paillier.peer1_step(share, session_id, old_share, delta)) return rv;

  return 0;
}

error_t ecdsa_refresh_t::peer2_step2(
  ecdsa_share_t& share, 
  const message3_t& in)
{
  buf_t agree_buf;
  error_t rv =  agree_random.peer2_step2(in.agree_msg3, agree_buf);
  if (rv) return rv;

  ecurve_t curve = share.get_curve();
  int key_size = curve.size();
  if (agree_buf.size()!=16 + key_size*2) return rv = ub::error(E_BADARG);

  mem_t session_id = mem_t(agree_buf.data(), 16);
  mem_t agree_refresh = mem_t(agree_buf.data()+16, agree_buf.size()-16);

  ecdsa_share_t old_share = share;
  bn_t delta;
  if (rv = ecdsa_share_t::get_refresh_delta(curve, agree_refresh, delta)) return rv;
  if (rv = share.refresh_peer2(delta)) return rv;
  if (rv = in.refresh_paillier.peer2_step(share, session_id, old_share, delta)) return rv;
  return 0;
}


}