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

package com.unboundTech.mpc;

public class MPCException extends Exception
{
  public static final int MPC_E_BADARG     = (int)0xff010002; // bad argument
  public static final int MPC_E_FORMAT     = (int)0xff010003; // invalid format
  public static final int MPC_E_TOO_SMALL  = (int)0xff010008; // buffer too small
  public static final int MPC_E_CRYPTO     = (int)0xff040001; // crypto error, process is being tampered

  public int errorCode = 0;

  MPCException(int errorCode)
  {
    this.errorCode = errorCode;
  }

  static void check(int errorCode) throws MPCException
  {
    if (errorCode!=0) throw new MPCException(errorCode);
  }
}
