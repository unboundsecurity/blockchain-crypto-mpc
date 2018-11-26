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
#include "mpc_ecc_core.h"
#include "mpc_ecdh.h"
#include "mpc_ecdsa.h"

using namespace ub;
using namespace crypto;

namespace mpc {

// ------------------------------- ecdh_share_t --------------------------------

void ecdh_share_t::refresh(bool add, const bn_t& diff)
{
  ecurve_t curve = get_curve();
  const bn_t& order = curve.order();
  const ecc_generator_point_t& G = curve.generator();

  bn_t x_diff = diff % order;
  ecc_point_t Q_diff = G * x_diff;
  
  MODULO (order) 
  { 
    if (add) x += x_diff; else x -= x_diff;
  }
}

void ecdh_share_t::split(
    ecurve_t curve, 
    const bn_t& x, 
    ecdh_share_t& share1, ecdh_share_t& share2) // static
{
  const bn_t& order = curve.order();
  const ecc_generator_point_t& G = curve.generator();

  bn_t x1, x2;
  x1 = bn_t::rand(order);
  MODULO(order) { x2 = x - x1; }

  ecc_point_t Q1 = G * x1;
  ecc_point_t Q2 = G * x2;

  share1.x = x1;
  share1.Q_full =  Q1 + Q2;

  share2.x = x2;
  share2.Q_full = Q1 + Q2;
}


// ------------------------------- generate ---------------------------------

void ecdh_generate_t::peer1_step1(
    ecurve_t curve, 
    mem_t session_id, 
    ecdh_share_t& share,
    message1_t& out)
{
  this->session_id = session_id;
  this->curve = curve;
  const bn_t& order = curve.order();
  const ecc_generator_point_t& G = curve.generator();
  share.x = curve.get_random_value();

  Q_self = G * share.x;

  zk_dl.p(curve, Q_self, session_id, 1, share.x);  
  commitment_t comm;  comm.gen(sha256_t(session_id, Q_self, zk_dl.e, zk_dl.u));

  out.comm_hash = comm.hash;
  comm_rand = comm.rand;
}

error_t ecdh_generate_t::peer2_step1(
    ecurve_t curve, 
    mem_t session_id, 
    ecdh_share_t& share,
    const message1_t& in, 
    message2_t& out) 
{  
  error_t rv = 0;
  this->session_id = session_id;
  this->curve = curve;

  comm_hash = in.comm_hash;
  const ecc_generator_point_t& G = curve.generator();
  share.x = curve.get_random_value();

  out.Q2 = Q_self = G * share.x;
  out.zk_dl.p(curve, Q_self, session_id, 2, share.x);
  return 0;
}

error_t ecdh_generate_t::peer1_step2(
    ecdh_share_t& share,
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

  return 0;
}

error_t ecdh_generate_t::peer2_step2(
  ecdh_share_t& share,
  const message3_t& in)
{
  error_t rv = 0;

  ecurve_t curve = Q_self.get_curve();
  if (!curve.check(in.Q1)) return rv = error(E_CRYPTO);

  if (!commitment_t::check(in.comm_rand, comm_hash, sha256_t(session_id, in.Q1, in.zk_dl.e, in.zk_dl.u))) return rv = error(E_CRYPTO);
  if (!in.zk_dl.v(curve, in.Q1, session_id, 1)) return rv = error(E_CRYPTO);

  const ecc_generator_point_t& G = curve.generator();

  share.Q_full = in.Q1 + G * share.x;

  return 0;
}


// ----------------------------- derive -------------------------

error_t ecdh_derive_t::peer1_init(
  const ecc_point_t& PUB_KEY, 
  bool prove_mode, 
  mem_t session_id, 
  const ecdh_share_t& share,
  /*OUT*/ message1_t& out)
{
  ecurve_t curve = share.get_curve();
  if (!curve.check(PUB_KEY)) return error(E_CRYPTO);

  this->PUB_KEY = PUB_KEY;
  this->prove_mode = prove_mode;
  this->session_id = session_id;

  out.T1 = PUB_KEY * share.x;
  return 0;
}

static buf_t get_ecdh_result(const ecc_point_t& P)
{
  ecurve_t curve = P.get_curve();
  bn_t x; P.get_x(x);
  return x.to_bin(curve.size());
}

error_t ecdh_derive_t::peer2_exec(
    const ecc_point_t& PUB_KEY, 
    const ecdh_share_t& share,
    bool prove_mode, 
    mem_t session_id, 
    const message1_t& in,
    /*OUT*/ message2_t& out,
    /*OUT*/ buf_t& result) const
{
  ecurve_t curve = share.get_curve();
  const ecc_generator_point_t& G = curve.generator();

  
  if (!curve.check(PUB_KEY)) return error(E_CRYPTO);
  if (!curve.check(in.T1)) return error(E_CRYPTO);

  out.T2 = PUB_KEY * share.x;
  if (prove_mode)
  {
    ecc_point_t Q_self = G * share.x;
    out.zk_ddh.p(curve, PUB_KEY, Q_self, out.T2, share.x, session_id, 2);
  }

  ecc_point_t T = in.T1 + out.T2;
  result = get_ecdh_result(T);
  return 0;
}

error_t ecdh_derive_t::peer1_final(
  const ecdh_share_t& share,
  const message2_t& in,     
  /*OUT*/ buf_t& result) const
{
  ecurve_t curve = share.get_curve();
  if (!curve.check(in.T2)) return error(E_CRYPTO);
  const ecc_generator_point_t& G = curve.generator();

  if (prove_mode) 
  {
    ecc_point_t Q_other = share.Q_full - G * share.x;
    if (!in.zk_ddh.v(curve, PUB_KEY, Q_other, in.T2, session_id, 2)) return error(E_CRYPTO);
  }

  ecc_point_t T1 = PUB_KEY * share.x;
  ecc_point_t T = T1 + in.T2;

  result = get_ecdh_result(T);
  return 0;
}

} //namespace mpc