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
#include "mpc_ecc_core.h"

using namespace ub;
using namespace crypto;

namespace mpc {

void commitment_t::gen(const sha256_t& sha256)
{
  rand = buf128_t::rand();
  hash = const_cast<sha256_t&>(sha256).update(rand).final();
}

bool commitment_t::check(buf128_t rand, buf256_t hash, const sha256_t& sha256)
{
  return hash == buf256_t(const_cast<sha256_t&>(sha256).update(rand).final());
}

//---------------------------------- agree random -------------------------


void agree_random_t::peer1_step1(message1_t& out)
{
  agree1 = crypto::gen_random(32);
  commitment_t comm;
  comm.gen(sha256_t(agree1));
  out.comm_hash = comm.hash;
  comm_rand = comm.rand;
}

error_t agree_random_t::peer2_step1(const message1_t& in, message2_t& out)
{
  error_t rv = 0;
  comm_hash = in.comm_hash;
  out.agree2 = agree2 = crypto::gen_random(32);
  return 0;
}

buf_t agree_random_t::generate(int size, mem_t agree1, mem_t agree2) // static
{
  buf_t out(size);
  byte_ptr out_ptr = out.data();
  
  int n = 0;
  while (size>0)
  {
    buf256_t hash = sha256_t::hash(agree1, agree2, n);
    n++;

    if (size < 32) 
    {
      memmove(out_ptr, hash, size);
      break;
    }

    memmove(out_ptr, hash, 32);
    out_ptr += 32;
    size -= 32;
  }

  return out;
}

buf_t agree_random_t::generate(int size, mem_t agree) // static
{
  buf_t out(size);
  byte_ptr out_ptr = out.data();
  
  int n = 0;
  while (size>0)
  {
    buf256_t hash = sha256_t::hash(agree, n);
    n++;

    if (size < 32) 
    {
      memmove(out_ptr, hash, size);
      break;
    }

    memmove(out_ptr, hash, 32);
    out_ptr += 32;
    size -= 32;
  }

  return out;
}

error_t agree_random_t::peer1_step2(const message2_t& in, message3_t& out, buf_t& result)
{
  error_t rv = 0;
  if (in.agree2.size()<32) return rv = error(E_CRYPTO);
  out.agree1 = agree1;
  out.comm_rand = comm_rand;
  result = generate(size, agree1, in.agree2);
  return 0;
}

error_t agree_random_t::peer2_step2(const message3_t& in, buf_t& result)
{
  error_t rv = 0;
  if (in.agree1.size()<32) return rv = error(E_CRYPTO);
  if (!commitment_t::check(in.comm_rand, comm_hash, crypto::sha256_t(in.agree1))) return rv = error(E_CRYPTO);
  result = generate(size, in.agree1, agree2);
  return 0;
}


buf_t gen_shared_random(mem_t rnd1, mem_t rnd2, int out_size)
{
  buf_t out(out_size);
  buf256_t base_hash = sha256_t::hash(rnd1, rnd2);

  for (int i=0; i<out_size; i+=32)
  {
    buf256_t hash = sha256_t::hash(base_hash, i);

    if (i+32<=out_size) memmove(&out[i], hash, 32);
    else 
    {
      memmove(&out[i], hash, out_size-i);
      break;
    }
  }
  return out;
}




} //namespace mpc
