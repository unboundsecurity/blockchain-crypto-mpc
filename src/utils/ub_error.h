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
#include "ub_common.h"

typedef int error_t;

#define ERRCODE(group, code) (uint32_t(group) | uint32_t(code))

enum 
{
  GERR_GENERIC = 0xff010000,
  GERR_CRYPTO  = 0xff040000,
};

enum
{
  ECATEGORY_GENERIC  = 1,
  ECATEGORY_CRYPTO   = 2,
  ECATEGORY_OPENSSL  = 6,
};

enum 
{ 
  E_GENERAL        = ERRCODE(GERR_GENERIC, 1),
  E_BADARG         = ERRCODE(GERR_GENERIC, 2),
  E_FORMAT         = ERRCODE(GERR_GENERIC, 3),
  E_TIMEOUT        = ERRCODE(GERR_GENERIC, 4),
  E_NOT_SUPPORTED  = ERRCODE(GERR_GENERIC, 5),
  E_NOT_FOUND      = ERRCODE(GERR_GENERIC, 6),
  E_NOT_ALLOWED    = ERRCODE(GERR_GENERIC, 7),
  E_TOO_SMALL      = ERRCODE(GERR_GENERIC, 8),
  E_MEMORY         = ERRCODE(GERR_GENERIC, 9),
  E_AUTH           = ERRCODE(GERR_GENERIC, 10),
  E_NOT_READY      = ERRCODE(GERR_GENERIC, 11),
  E_UNAVAILABLE    = ERRCODE(GERR_GENERIC, 12),
};

namespace ub {

error_t error(error_t rv);
error_t error(error_t rv, int category, const std::string& text);
error_t error(error_t rv, const std::string& text);


} //namespace ub
