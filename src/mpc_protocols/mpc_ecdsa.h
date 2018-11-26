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

int get_safe_paillier_bits(ecurve_t curve);

struct ecdsa_share_t 
{
  bn_t x, c_key, r_key;
  ecc_point_t Q_full;
  crypto::paillier_t paillier;  

  void convert(ub::converter_t& converter)
  { 
    converter.convert(x);
    converter.convert(c_key);
    converter.convert(r_key);
    converter.convert(Q_full);
    converter.convert(paillier);
  }

  crypto::ecc_curve_ptr get_curve() const { return Q_full.get_curve(); }

  static error_t get_refresh_delta(ecurve_t curve, mem_t refresh_buf, bn_t& delta);
  error_t refresh_peer1(const bn_t& delta);
  error_t refresh_peer2(const bn_t& delta);

};

struct ecdsa_refresh_paillier_t 
{
  bn_t N, c_key;
  buf_t pi;
  zk_paillier_eq_t zk_paillier_eq;

  void convert(ub::converter_t& converter) 
  { 
    converter.convert(N);
    converter.convert(c_key);
    converter.convert(pi);
    converter.convert(zk_paillier_eq);
  }

  error_t peer1_step(ecdsa_share_t& share, mem_t session_id, const ecdsa_share_t& old_share, const bn_t& delta);
  error_t peer2_step(ecdsa_share_t& share, mem_t session_id, const ecdsa_share_t& old_share, const bn_t& delta) const;
};

struct ecdsa_create_paillier_t 
{
  struct message1_t
  {
    bn_t N, c_key;
    buf_t pi;

    void convert(ub::converter_t& converter) 
    { 
      converter.convert(N);
      converter.convert(c_key);
      converter.convert(pi);
    }
  };

  void convert(ub::converter_t& converter) 
  { 
  }

  error_t peer1_step1(ecdsa_share_t& share, mem_t session_id, message1_t& out);
  error_t peer2_step2(ecdsa_share_t& share, mem_t session_id, const message1_t& in);
};

struct ecdsa_generate_t 
{
  buf_t session_id;
  zk_dl_t zk_dl;
  buf128_t comm_rand;
  buf256_t comm_hash;
  ecc_point_t Q_self;
  ecdsa_create_paillier_t create_paillier;

  void convert(ub::converter_t& converter) 
  {
    converter.convert(session_id);
    converter.convert(Q_self);
    converter.convert(zk_dl);
    converter.convert(comm_rand);
    converter.convert(comm_hash);
    converter.convert(create_paillier);
  }

  struct message1_t 
  {
    buf256_t comm_hash;
    void convert(ub::converter_t& converter) 
    {
      converter.convert(comm_hash);
    }
  };

  struct message2_t 
  {
    ecc_point_t Q2;
    zk_dl_t zk_dl;

    void convert(ub::converter_t& converter) 
    {
      converter.convert(Q2);
      converter.convert(zk_dl);
    }
  };

  struct message3_t 
  {
    buf128_t comm_rand;
    ecc_point_t Q1;
    zk_dl_t zk_dl;
    ecdsa_create_paillier_t::message1_t create_paillier_msg1;

    void convert(ub::converter_t& converter) 
    {
      converter.convert(comm_rand);
      converter.convert(Q1);
      converter.convert(zk_dl);
      converter.convert(create_paillier_msg1);
    }
  };

  void peer1_step1(
    bool only_helper,
    crypto::ecc_curve_ptr curve, 
    mem_t session_id, 
    ecdsa_share_t& share,
    message1_t& out);

  error_t peer2_step1(
    bool only_helper,
    crypto::ecc_curve_ptr curve, 
    mem_t session_id, 
    ecdsa_share_t& share,
    const message1_t& in, 
    message2_t& out);      

  error_t peer1_step2(
    ecdsa_share_t& share,
    const message2_t& in,
    message3_t& out);

  error_t peer2_step2(
    ecdsa_share_t& share,
    const message3_t& in);
};

struct ecdsa_sign_t 
{
  buf_t agree1, session_id, agree_refresh;
  buf_t data_to_sign;
  bool refresh;

  buf256_t comm_hash;
  buf128_t comm_rand;
  zk_dl_t zk_dl;
  bn_t k1, k2;
  ecc_point_t R1, R2;

  void convert(ub::converter_t& converter) 
  {
    converter.convert(agree1);
    converter.convert(agree_refresh);
    converter.convert(session_id);
    converter.convert(data_to_sign);
    converter.convert(refresh);
    converter.convert(k1);
    converter.convert(k2);
    converter.convert(R1);
    converter.convert(R2);
    converter.convert(zk_dl);
    converter.convert(comm_rand);
    converter.convert(comm_hash);
  }

  struct message1_t 
  {
    buf_t agree1;
    buf256_t comm_hash;
    void convert(ub::converter_t& converter) 
    {
      converter.convert(comm_hash);
      converter.convert(agree1);
    }
  };

  struct message2_t 
  {
    buf_t agree2;
    ecc_point_t R2;
    zk_dl_t zk_dl;

    void convert(ub::converter_t& converter) 
    {
      converter.convert(R2);
      converter.convert(zk_dl);
      converter.convert(agree2);
    }
  };

  struct message3_t 
  {
    ecc_point_t R1;
    zk_dl_t zk_dl;
    buf128_t comm_rand;
    void convert(ub::converter_t& converter) 
    {
      converter.convert(comm_rand);
      converter.convert(R1);
      converter.convert(zk_dl);
    }
  };

  struct message4_t
  {
    bn_t c3;
    void convert(ub::converter_t& converter) 
    {
      converter.convert(c3);
    }
  };

  struct message5_t 
  {
    buf_t signature;
    ecdsa_refresh_paillier_t refresh_paillier;
    void convert(ub::converter_t& converter) 
    {
      converter.convert(signature);
      converter.convert(refresh_paillier);
    }
  };

  void peer1_step1(
    const ecdsa_share_t& share, 
    mem_t data_to_sign,
    bool refresh,
    message1_t& out);

  error_t peer2_step1(
    const ecdsa_share_t& share, 
    mem_t data_to_sign,
    bool refresh,
    const message1_t& in,
    message2_t& out);

  error_t peer1_step2(
    const ecdsa_share_t& share, 
    const message2_t& in,
    message3_t& out);

  error_t peer2_step2(
    const ecdsa_share_t& share, 
    const message3_t& in,
    message4_t& out);

  error_t peer1_step3(
    ecdsa_share_t& share, // may be refreshed
    const message4_t& in,
    message5_t& out);

  error_t peer2_step3(
    ecdsa_share_t& share, // may be refreshed
    const message5_t &in);
};


struct ecdsa_refresh_t 
{
  agree_random_t agree_random;

  void convert(ub::converter_t& converter) 
  {
    converter.convert(agree_random);
  }

  typedef agree_random_t::message1_t  message1_t;
  struct message2_t
  {
    agree_random_t::message2_t agree_msg2;
    void convert(ub::converter_t& converter)
    {
      converter.convert(agree_msg2);
    }

  };
  struct message3_t
  {
    agree_random_t::message3_t agree_msg3;
    ecdsa_refresh_paillier_t refresh_paillier;

    void convert(ub::converter_t& converter)
    {
      converter.convert(agree_msg3);
      converter.convert(refresh_paillier);
    }
  };

  void peer1_step1(
    const ecdsa_share_t& share, 
    message1_t& out);

  error_t peer2_step1(
    const ecdsa_share_t& share, 
    const message1_t& in,
    message2_t& out);

  error_t peer1_step2(
    ecdsa_share_t& share, 
    const message2_t& in,
    message3_t& out);

  error_t peer2_step2(
    ecdsa_share_t& share, 
    const message3_t& in);
};

} //namespace mpc