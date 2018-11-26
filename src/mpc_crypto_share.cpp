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
#include "mpc_crypto_share.h"

MPCCRYPTO_API void MPCCrypto_freeShare(MPCCryptoShare* share)
{
  delete (mpc_crypto_share_t*)share;
}

MPCCRYPTO_API int MPCCrypto_shareToBuf(MPCCryptoShare* share, uint8_t* out, int* out_size)
{
  ub::converter_t converter(out);
  converter.convert(*(mpc_crypto_share_t*)share);
  *out_size = converter.get_size();
  return 0;
}

MPCCRYPTO_API int MPCCrypto_shareFromBuf(const uint8_t* in, int in_size, MPCCryptoShare** out_share)
{
  ub::convertable_t* obj =  ub::convertable_t::factory_t::create(ub::mem_t(in, in_size));
  if (!obj) return ub::error(E_FORMAT);

  mpc_crypto_share_t* share = dynamic_cast<mpc_crypto_share_t*>(obj);
  if (!share)
  {
    delete obj;
    return ub::error(E_FORMAT);
  }

  *out_share = (MPCCryptoShare*)obj;
  return 0;
}

MPCCRYPTO_API int MPCCrypto_shareInfo(MPCCryptoShare* share, mpc_crypto_share_info_t* info)
{
  error_t rv = 0;
  if (!share || !info) return rv = ub::error(E_BADARG);

  ((mpc_crypto_share_t*)share)->get_info(*info);
  return 0;
}

void mpc_crypto_share_t::get_info(mpc_crypto_share_info_t& info) const
{
  info.uid = uid;
  info.type = get_type();
}

void mpc_crypto_share_t::convert(ub::converter_t& converter) 
{
  converter.convert_code_type(CODE_TYPE);
  converter.convert(uid);
}
