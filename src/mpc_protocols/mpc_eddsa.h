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

struct eddsa_share_t
{
  crypto::bn_t x;
  ecp_25519_t Q_full;

  void convert(ub::converter_t& converter) 
  { 
    converter.convert(x);
    converter.convert(Q_full);
  }

  static void split(
    mem_t prv_key, 
    /*OUT*/ eddsa_share_t& share1, 
    /*OUT*/ eddsa_share_t& share2);

  void refresh(bool add, mem_t diff);
};

struct zk_dl_25519_t
{
  bn_t e;
  bn_t u;
  void convert(ub::converter_t& converter)
  {
    converter.convert(e);
    converter.convert(u);
  }

  void p(const ecp_25519_t& Q, mem_t session_id, uint8_t aux, const bn_t& d);
  bool v(const ecp_25519_t& Q, mem_t session_id, uint8_t aux) const;
};

struct zk_ddh_25519_t
{
  bn_t e;
  bn_t u;
  void convert(ub::converter_t& converter)
  {
    converter.convert(e);
    converter.convert(u);
  }

  void p(const ecp_25519_t& Q, const ecp_25519_t& A, const ecp_25519_t& B, const bn_t& w, mem_t session_id, uint8_t aux);
  bool v(const ecp_25519_t& Q, const ecp_25519_t& A, const ecp_25519_t& B, mem_t session_id, uint8_t aux) const;
};

struct eddsa_gen_t
{
  buf_t session_id;
  zk_dl_25519_t zk_dl;
  buf128_t comm_rand;
  buf256_t comm_hash;
  ecp_25519_t A1, A2;

  void convert(ub::converter_t& converter)
  { 
    converter.convert(session_id);
    converter.convert(zk_dl);
    converter.convert(comm_rand);
    converter.convert(comm_hash);
    converter.convert(A1);
    converter.convert(A2);
  }

  struct message1_t  // 1 --> 2
  {
    buf256_t comm_hash;

    void convert(ub::converter_t& converter)
    { 
      converter.convert(comm_hash);
    }
  };

  struct message2_t // 2 --> 1
  {
    ecp_25519_t A2, a, b;
    zk_ddh_25519_t zk_ddh;

    void convert(ub::converter_t& converter)
    { 
      converter.convert(A2);
      converter.convert(a);
      converter.convert(b);
      converter.convert(zk_ddh);
    }
  };

  struct message3_t // 1 --> 2
  {
    ecp_25519_t A1;
    buf128_t comm_rand;
    zk_dl_25519_t zk_dl;

    void convert(ub::converter_t& converter) 
    { 
      converter.convert(A1);
      converter.convert(comm_rand);
      converter.convert(zk_dl);
    }
  };

  error_t peer1_step1(
    mem_t session_id, 
    eddsa_share_t& share,
    message1_t& out);

  error_t peer2_step1(
    mem_t session_id, 
    eddsa_share_t& share,
    const message1_t& in,
    message2_t& out);

  error_t peer1_step2(
    eddsa_share_t& share,
    const message2_t& in,
    message3_t& out);

  error_t peer2_step2(
    eddsa_share_t& share,
    const message3_t& in);

};

struct eddsa_sign_t
{
  buf_t data_to_sign;
  buf_t agree1, session_id;
  ecp_25519_t R1, R2;
  buf128_t comm_rand;
  buf256_t comm_hash;
  buf_t r_reduced_buf;

  void convert(ub::converter_t& converter) 
  { 
    converter.convert(data_to_sign);
    converter.convert(agree1);
    converter.convert(session_id);
    converter.convert(R1);
    converter.convert(R2);
    converter.convert(comm_rand);
    converter.convert(comm_hash);
    converter.convert(r_reduced_buf);
  }

  struct message1_t // 1 --> 2
  {
    buf_t agree1;
    void convert(ub::converter_t& converter) 
    { 
      converter.convert(agree1);
    }
  };

  error_t peer1_step1(mem_t m, 
    const eddsa_share_t& share,
    /*OUT*/message1_t& out);

  struct message2_t // 2 --> 1
  {
    buf_t agree2;
    buf256_t comm_hash;

    void convert(ub::converter_t& converter)
    { 
      converter.convert(agree2);
      converter.convert(comm_hash);
    }
  };

  error_t peer2_step1(
    mem_t data_to_sign, 
    const eddsa_share_t& share,
    const message1_t& in,
    message2_t& out);

  struct message3_t // 1 --> 2
  {
    ecp_25519_t R1;
    void convert(ub::converter_t& converter) 
    { 
      converter.convert(R1);
    }
  };

  error_t peer1_step2(
    const eddsa_share_t& share,
    const message2_t& in,
    /*OUT*/message3_t& out);

  struct message4_t // 2 --> 1
  {
    buf_t s2;
    ecp_25519_t R2;
    buf128_t comm_rand;
    void convert(ub::converter_t& converter) 
    { 
      converter.convert(s2);
      converter.convert(R2);
      converter.convert(comm_rand);
    }
  };

  error_t peer2_step2(
    const eddsa_share_t& share,
    const message3_t& in,
    message4_t& out);

  error_t peer1_step3(
    const eddsa_share_t& share,
    const message4_t& in,
    byte_ptr out); // 64 bytes
};

} //namespace mpc
