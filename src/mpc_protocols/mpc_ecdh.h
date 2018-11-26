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
#include "crypto.h"
#include "mpc_ecc_core.h"

namespace mpc {


struct ecdh_share_t
{
  bn_t x;
  ecc_point_t Q_full;
  void convert(ub::converter_t& converter)
  {
    converter.convert(x);
    converter.convert(Q_full);
  }
  
  crypto::ecc_curve_ptr get_curve() const { return Q_full.get_curve(); }
  ecc_point_t get_Q() const { return Q_full; }

  static void split(
    ecurve_t curve, 
    const bn_t& x, 
    ecdh_share_t& share1, ecdh_share_t& share2);

  void refresh(bool add, const bn_t& diff);
  void refresh(bool add, mem_t diff) { refresh(add, bn_t::from_bin(diff)); }
};

struct ecdh_generate_t
{
  ecurve_t curve;
  buf_t session_id;
  zk_dl_t zk_dl;
  buf128_t comm_rand;
  buf256_t comm_hash;
  ecc_point_t Q_self;

  ecdh_generate_t() : curve(nullptr)  {}

  void convert(ub::converter_t& converter)
  {
    curve.convert(converter);
    converter.convert(session_id);
    converter.convert(zk_dl);
    converter.convert(comm_rand);
    converter.convert(comm_hash);
    converter.convert(Q_self);
  }

  struct message1_t // 1 --> 2
  {
    buf256_t comm_hash;
    void convert(ub::converter_t& converter) 
    {
      converter.convert(comm_hash);
    }
  };

  struct message2_t // 2 --> 1
  {
    ecc_point_t Q2;
    zk_dl_t zk_dl;

    void convert(ub::converter_t& converter) 
    {
      converter.convert(Q2);
      converter.convert(zk_dl);
    }
  };

  struct message3_t // 1 --> 2
  {
    buf128_t comm_rand;
    ecc_point_t Q1;
    zk_dl_t zk_dl;

    void convert(ub::converter_t& converter) 
    {
      converter.convert(comm_rand);
      converter.convert(Q1);
      converter.convert(zk_dl);
    }
  };

  void peer1_step1(
    ecurve_t curve, 
    mem_t session_id, 
    ecdh_share_t& share,
    message1_t& out);

  error_t peer2_step1(
    ecurve_t curve, 
    mem_t session_id, 
    ecdh_share_t& share,
    const message1_t& in, 
    message2_t& out);      

  error_t peer1_step2(
    ecdh_share_t& share,
    const message2_t& in,
    message3_t& out);

  error_t peer2_step2(
    ecdh_share_t& share,
    const message3_t& in);      
};

struct ecdh_derive_t
{
  bool prove_mode;
  buf_t session_id;
  ecc_point_t PUB_KEY;

  void convert(ub::converter_t& converter)
  { 
    converter.convert(prove_mode);
    converter.convert(session_id);
    converter.convert(PUB_KEY);
  }

  struct message1_t // 1 --> 2
  {
    ecc_point_t T1;
    void convert(ub::converter_t& converter)
    { 
      converter.convert(T1);
    }
  };

  struct message2_t // 2 --> 1
  { 
    ecc_point_t T2;
    zk_ddh_t zk_ddh;

    void convert(ub::converter_t& converter)
    { 
      converter.convert(T2);
      converter.convert(zk_ddh);
    }
  };

  error_t peer1_init(
    const ecc_point_t& PUB_KEY, 
    bool prove_mode, 
    mem_t session_id, 
    const ecdh_share_t& share,
    /*OUT*/ message1_t& out); 

  error_t peer2_exec(
    const ecc_point_t& PUB_KEY, 
    const ecdh_share_t& share,
    bool prove_mode, 
    mem_t session_id, 
    const message1_t& in,
    /*OUT*/ message2_t& out,
    /*OUT*/ buf_t& result) const;

  error_t peer1_final(
    const ecdh_share_t& share,
    const message2_t& in,     
    /*OUT*/ buf_t& result) const; 
};

}